//! Zrax CLI
//!
//! Command-line tool for identifying processor architectures in binary files.

use clap::{Parser, Subcommand, ValueEnum};
use zrax::{
    detect_interleaved, detect_multi_isa, detect_payload, CandidatesFormatter, ClassifierOptions,
    DetectionPayload,
    HumanFormatter, JsonFormatter, PayloadFormatter, ShortFormatter,
};
use std::path::PathBuf;
use std::process::ExitCode;

/// Universal binary architecture classifier.
///
/// Identifies processor architectures, ISA variants, and extensions
/// from ELF, PE, Mach-O, and raw binary files.
#[derive(Parser, Debug)]
#[command(name = "zrax")]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Input file(s) to analyze (for default classify mode)
    files: Vec<PathBuf>,

    /// Output format
    #[arg(short, long, default_value = "human")]
    format: OutputFormat,

    /// Analysis mode
    #[arg(short, long, default_value = "normal")]
    mode: AnalysisMode,

    /// Show detected extensions
    #[arg(short, long)]
    extensions: bool,

    /// Show all candidates (for heuristic analysis)
    #[arg(short, long)]
    candidates: bool,

    /// Detect multiple ISAs in firmware images (windowed analysis)
    #[arg(long)]
    multi_isa: bool,

    /// Window size in bytes for multi-ISA detection (default: 1024)
    #[arg(long, default_value = "1024")]
    window_size: usize,

    /// Minimum confidence threshold (0.0 - 1.0)
    #[arg(long, default_value = "0.3")]
    min_confidence: f64,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Quiet mode (only output essential info)
    #[arg(short, long)]
    quiet: bool,

    /// Treat the input files as byte lanes of one image (lane 0 first, for
    /// example the even and odd EPROMs of a 16-bit bus) and classify the
    /// interleaved image
    #[arg(long)]
    interleave: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List X.509 certificates found in files and optionally write them out.
    ///
    /// Finds DER structures and PEM blocks anywhere in each input.
    /// Signatures and chains are not verified; issuer links compare encoded
    /// names only.
    Certs(CertsArgs),
    /// Print printable strings in ASCII, UTF-8 and UTF-16.
    Strings(StringsArgs),
    /// Batch classify and store files for S3 ingestion.
    ///
    /// Recursively walks an input directory, classifies each file by ISA and
    /// format, and writes results to a local staging directory that mirrors
    /// the S3 key layout. Upload with `rclone sync`.
    #[cfg(feature = "batch")]
    Batch(BatchArgs),
}

/// Output formats of the `certs` subcommand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CertsFormat {
    /// Human-readable listing
    Human,
    /// One JSON object per file
    Json,
}

/// Arguments for the `certs` subcommand.
#[derive(Parser, Debug)]
struct CertsArgs {
    /// Files to scan
    #[arg(required = true)]
    files: Vec<PathBuf>,

    /// Output format
    #[arg(short, long, default_value = "human")]
    format: CertsFormat,

    /// Write each certificate to DIR as cert_<index>.der and .pem; with
    /// several inputs, into DIR/input_<n>/
    #[arg(long, value_name = "DIR")]
    dump: Option<PathBuf>,

    /// With --dump, write only DER files
    #[arg(long, requires = "dump", conflicts_with = "pem")]
    der: bool,

    /// With --dump, write only PEM files
    #[arg(long, requires = "dump")]
    pem: bool,

    /// With --dump, write into a directory that is not empty
    #[arg(long, requires = "dump")]
    force: bool,

    /// Show issuer links as a tree (human output only)
    #[arg(long)]
    tree: bool,
}

/// Output formats of the `strings` subcommand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum StringsFormat {
    /// One string per line, as GNU strings prints them
    Text,
    /// offset,size,chars,encoding,tags,clipped,text
    Csv,
    /// One JSON object per file
    Json,
}

/// Offset radix of the `strings` text output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Radix {
    /// Octal
    #[value(name = "o")]
    Octal,
    /// Decimal
    #[value(name = "d")]
    Decimal,
    /// Hexadecimal
    #[value(name = "x")]
    Hex,
}

/// Arguments for the `strings` subcommand.
#[derive(Parser, Debug)]
struct StringsArgs {
    /// Files to scan
    #[arg(required = true)]
    files: Vec<PathBuf>,

    /// Minimum string length in characters (3 to 255)
    #[arg(short = 'n', long = "min-len", default_value_t = zrax::strings::DEFAULT_MIN_CHARS)]
    min_len: usize,

    /// Encodings to report, comma-separated: ascii, utf8, utf16le, utf16be
    #[arg(
        short,
        long,
        value_delimiter = ',',
        default_value = "ascii,utf8,utf16le",
        value_parser = parse_encoding
    )]
    encodings: Vec<zrax::strings::Encoding>,

    /// Only strings with this tag (repeatable): url, email, ipv4, path, uuid,
    /// format, digest, mangled, pem
    #[arg(long = "tag", value_parser = parse_tag)]
    tags: Vec<zrax::strings::Tags>,

    /// Print each offset in this radix before the text
    #[arg(short = 't', long)]
    radix: Option<Radix>,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: StringsFormat,
}

fn parse_encoding(id: &str) -> Result<zrax::strings::Encoding, String> {
    zrax::strings::Encoding::from_id(id).ok_or_else(|| {
        let ids: Vec<&str> = zrax::strings::ENCODINGS.iter().map(|e| e.id()).collect();
        format!(
            "unknown encoding {id:?}; expected one of {}",
            ids.join(", ")
        )
    })
}

fn parse_tag(id: &str) -> Result<zrax::strings::Tags, String> {
    zrax::strings::Tags::from_id(id).ok_or_else(|| {
        let ids: Vec<&str> = zrax::strings::TAG_NAMES.iter().map(|(_, id)| *id).collect();
        format!("unknown tag {id:?}; expected one of {}", ids.join(", "))
    })
}

/// Arguments for the `batch` subcommand.
#[cfg(feature = "batch")]
#[derive(Parser, Debug)]
struct BatchArgs {
    /// Input directory containing binary files to classify
    #[arg(short, long)]
    input: PathBuf,

    /// Output staging directory (created if it doesn't exist)
    #[arg(short, long)]
    output: PathBuf,

    /// Number of parallel worker threads
    #[arg(short, long, default_value_t = default_jobs())]
    jobs: usize,

    /// S3 key prefix for all generated keys
    #[arg(long, default_value = "isa-harvester/v1")]
    prefix: String,

    /// Minimum confidence to classify (below → ambiguous)
    #[arg(long, default_value = "0.30")]
    min_confidence: f64,

    /// Minimum margin over runner-up (below → ambiguous)
    #[arg(long, default_value = "0.20")]
    min_margin: f64,

    /// Override the run ID (default: auto-generated)
    #[arg(long)]
    run_id: Option<String>,

    /// Enable deep scan mode (slower, more accurate)
    #[arg(long)]
    deep_scan: bool,

    /// Enable ISA extension detection
    #[arg(long, default_value = "true")]
    extensions: bool,

    /// Disable ISA extension detection
    #[arg(long)]
    no_extensions: bool,

    /// Skip files larger than this (bytes)
    #[arg(long, default_value = "1073741824")]
    max_file_size: u64,

    /// Skip files smaller than this (bytes)
    #[arg(long, default_value = "4")]
    min_file_size: u64,

    /// Follow symbolic links
    #[arg(long)]
    follow_symlinks: bool,

    /// Disable TUI, use simple progress output
    #[arg(long)]
    no_tui: bool,

    /// Suppress all output except errors
    #[arg(short, long)]
    quiet: bool,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Max lines per ledger segment
    #[arg(long, default_value = "50000")]
    ledger_segment_max_lines: usize,

    /// Max uncompressed bytes per ledger segment
    #[arg(long, default_value = "10485760")]
    ledger_segment_max_bytes: usize,

    /// Skip files whose SHA-256 is already in a local index shard
    #[arg(long)]
    skip_existing: bool,
}

#[cfg(feature = "batch")]
fn default_jobs() -> usize {
    num_cpus::get()
}

/// Output format options.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    /// Human-readable output
    Human,
    /// JSON output
    Json,
    /// Compact single-line output
    Short,
}

/// Analysis mode options.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum AnalysisMode {
    /// Normal analysis (default)
    Normal,
    /// Fast analysis (less accurate)
    Fast,
    /// Thorough analysis (slower but more accurate)
    Thorough,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Handle subcommands
    if let Some(command) = &cli.command {
        return match command {
            Commands::Certs(args) => run_certs(args),
            Commands::Strings(args) => run_strings(args),
            #[cfg(feature = "batch")]
            Commands::Batch(args) => run_batch(args),
        };
    }

    // Default mode: classify individual files
    if cli.files.is_empty() {
        eprintln!("Error: no input files specified. Use --help for usage.");
        return ExitCode::FAILURE;
    }

    // Initialize logging if verbose
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_env_filter("zrax=debug")
            .init();
    }

    let options = build_options(&cli);
    if cli.interleave {
        return match analyze_interleaved(&options, &cli) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                if !cli.quiet {
                    eprintln!("Error analyzing interleaved image: {e}");
                }
                ExitCode::FAILURE
            }
        };
    }
    let mut success = true;

    for path in &cli.files {
        if cli.multi_isa {
            match analyze_multi_isa(path, &cli) {
                Ok(()) => {}
                Err(e) => {
                    if !cli.quiet {
                        eprintln!("Error analyzing {}: {}", path.display(), e);
                    }
                    success = false;
                }
            }
        } else {
            match analyze_file(path, &options, &cli) {
                Ok(()) => {}
                Err(e) => {
                    if !cli.quiet {
                        eprintln!("Error analyzing {}: {}", path.display(), e);
                    }
                    success = false;
                }
            }
        }
    }

    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

// ---------------------------------------------------------------------------
// Batch subcommand
// ---------------------------------------------------------------------------

#[cfg(feature = "batch")]
fn run_batch(args: &BatchArgs) -> ExitCode {
    use zrax::batch::{
        pipeline::{run_pipeline, PipelineConfig},
        routing::RoutingConfig,
        stats::PipelineStats,
        writer::LedgerRotationConfig,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    // Initialize logging
    if args.verbose {
        tracing_subscriber::fmt()
            .with_env_filter("zrax=debug")
            .init();
    }

    // Validate input directory
    if !args.input.is_dir() {
        eprintln!(
            "Error: input path is not a directory: {}",
            args.input.display()
        );
        return ExitCode::FAILURE;
    }

    // Create output directory if needed
    if let Err(e) = std::fs::create_dir_all(&args.output) {
        eprintln!("Error creating output directory: {}", e);
        return ExitCode::FAILURE;
    }

    let run_id = args
        .run_id
        .clone()
        .unwrap_or_else(PipelineConfig::generate_run_id);

    let detect_extensions = args.extensions && !args.no_extensions;

    let mut classifier_opts = if args.deep_scan {
        zrax::ClassifierOptions::thorough()
    } else {
        zrax::ClassifierOptions::new()
    };
    classifier_opts.detect_extensions = detect_extensions;
    classifier_opts.min_confidence = args.min_confidence;

    let config = PipelineConfig {
        input_dir: args.input.clone(),
        staging_dir: args.output.clone(),
        prefix: args.prefix.clone(),
        jobs: args.jobs,
        min_file_size: args.min_file_size,
        max_file_size: args.max_file_size,
        follow_symlinks: args.follow_symlinks,
        run_id: run_id.clone(),
        classifier_options: classifier_opts,
        routing_config: RoutingConfig {
            min_confidence: args.min_confidence,
            min_margin: args.min_margin,
        },
        ledger_config: LedgerRotationConfig {
            max_lines: args.ledger_segment_max_lines,
            max_bytes: args.ledger_segment_max_bytes,
        },
        skip_existing: args.skip_existing,
        deep_scan: args.deep_scan,
        detect_extensions,
    };

    let stats = Arc::new(PipelineStats::new());
    let shutdown = Arc::new(AtomicBool::new(false));

    // Set up Ctrl-C handler
    let shutdown_ctrlc = shutdown.clone();
    let _ = ctrlc_handler(shutdown_ctrlc);

    if !args.quiet {
        eprintln!("Zrax Batch Classifier");
        eprintln!("  Run ID:   {}", run_id);
        eprintln!("  Input:    {}", args.input.display());
        eprintln!("  Output:   {}", args.output.display());
        eprintln!("  Workers:  {}", args.jobs);
        eprintln!("  Prefix:   {}", args.prefix);
        eprintln!();
    }

    // Start TUI or simple progress in a separate thread
    let tui_stats = stats.clone();
    let tui_shutdown = shutdown.clone();
    let no_tui = args.no_tui || args.quiet;
    let tui_run_id = run_id.clone();
    let tui_jobs = args.jobs;
    let tui_input = args.input.display().to_string();
    let tui_output = args.output.display().to_string();

    let tui_handle = if !no_tui {
        Some(
            std::thread::Builder::new()
                .name("tui".into())
                .spawn(move || {
                    let _ = zrax::batch::tui::run_tui(
                        tui_stats,
                        tui_shutdown,
                        &tui_run_id,
                        tui_jobs,
                        &tui_input,
                        &tui_output,
                    );
                })
                .ok(),
        )
    } else if !args.quiet {
        let progress_stats = tui_stats;
        let progress_shutdown = tui_shutdown;
        Some(Some(
            std::thread::Builder::new()
                .name("progress".into())
                .spawn(move || {
                    zrax::batch::tui::run_simple_progress(
                        progress_stats,
                        progress_shutdown,
                        std::time::Duration::from_secs(10),
                    );
                })
                .unwrap(),
        ))
    } else {
        None
    };

    // Run the pipeline (blocks until complete)
    match run_pipeline(config, stats, shutdown) {
        Ok(result) => {
            // Wait for TUI thread to finish
            if let Some(Some(handle)) = tui_handle {
                let _ = handle.join();
            }

            if !args.quiet {
                let m = &result.run_manifest;
                eprintln!();
                eprintln!("Batch complete:");
                eprintln!("  Status:     {:?}", m.status);
                eprintln!("  Processed:  {}", m.counts.processed);
                eprintln!("  Classified: {}", m.counts.classified);
                eprintln!("  Ambiguous:  {}", m.counts.ambiguous);
                eprintln!("  Duplicates: {}", m.counts.duplicates);
                eprintln!("  Errors:     {}", m.counts.errors);
                eprintln!("  Duration:   {:.1}s", m.timing.duration_seconds);
                eprintln!("  Throughput: {:.1} files/sec", m.timing.files_per_second);
                eprintln!();
                eprintln!("Staging directory: {}", args.output.display());
                eprintln!(
                    "Upload with: rclone sync {}/ hetzner:bucket/{}/",
                    args.output.display(),
                    args.prefix
                );
            }

            ExitCode::SUCCESS
        }
        Err(e) => {
            if let Some(Some(handle)) = tui_handle {
                let _ = handle.join();
            }
            eprintln!("Pipeline error: {}", e);
            ExitCode::FAILURE
        }
    }
}

/// Set up a Ctrl-C handler that sets the shutdown flag.
#[cfg(feature = "batch")]
fn ctrlc_handler(shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    let _ = std::thread::spawn(move || {
        // Simple signal handling: on Unix, catch SIGINT
        // This is a basic approach; production code should use the `signal-hook` crate
        loop {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    });
}

// ---------------------------------------------------------------------------
// Certificate and string subcommands
// ---------------------------------------------------------------------------

/// One input's certificates with their enclosing regions, for JSON output.
#[derive(serde::Serialize)]
struct CertificateFile<'a> {
    file: String,
    certificates: Vec<LocatedCertificate<'a>>,
    truncated: bool,
    notes: &'a [String],
}

/// A certificate and the labels of the regions that contain it, outermost
/// first.
#[derive(serde::Serialize)]
struct LocatedCertificate<'a> {
    #[serde(flatten)]
    certificate: &'a zrax::certificates::Certificate,
    within: Vec<&'a str>,
}

fn is_nonempty_dir(dir: &std::path::Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_some())
}

/// Write each certificate as `cert_<index>.der` and/or `.pem` in `dir` and
/// return the paths written.
fn dump_certificates(
    dir: &std::path::Path,
    report: &zrax::certificates::Report,
    args: &CertsArgs,
) -> std::io::Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dir)?;
    let write_der = args.der || !args.pem;
    let write_pem = args.pem || !args.der;
    let mut written = Vec::new();
    for certificate in &report.certificates {
        if write_der {
            let path = dir.join(format!("cert_{}.der", certificate.index));
            std::fs::write(&path, &certificate.der)?;
            written.push(path);
        }
        if write_pem {
            let path = dir.join(format!("cert_{}.pem", certificate.index));
            std::fs::write(&path, &certificate.pem)?;
            written.push(path);
        }
    }
    Ok(written)
}

fn certs_file(
    path: &std::path::Path,
    input: usize,
    args: &CertsArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = std::fs::read(path)?;
    let report = zrax::certificates::scan(&data);
    // Regions only label certificates; a malformed container still lists them.
    let regions = zrax::inspection::regions(&data).unwrap_or_default();
    let written = match &args.dump {
        Some(dir) if args.files.len() > 1 => {
            dump_certificates(&dir.join(format!("input_{input}")), &report, args)?
        }
        Some(dir) => dump_certificates(dir, &report, args)?,
        None => Vec::new(),
    };
    match args.format {
        CertsFormat::Json => {
            let certificates = report
                .certificates
                .iter()
                .map(|certificate| LocatedCertificate {
                    certificate,
                    within: zrax::inspection::enclosing(
                        &regions,
                        certificate.offset,
                        certificate.stored_size,
                    )
                    .iter()
                    .map(|region| region.label.as_str())
                    .collect(),
                })
                .collect();
            let output = CertificateFile {
                file: path.display().to_string(),
                certificates,
                truncated: report.truncated,
                notes: &report.notes,
            };
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        CertsFormat::Human if args.tree => {
            print!("{}", zrax::formatter::certificates_tree(path, &report));
        }
        CertsFormat::Human => {
            print!(
                "{}",
                zrax::formatter::certificates_human(path, &report, &regions)
            );
            for written in &written {
                println!("  Wrote: {}", written.display());
            }
        }
    }
    Ok(())
}

fn run_certs(args: &CertsArgs) -> ExitCode {
    if args.tree && args.format != CertsFormat::Human {
        eprintln!("Error: --tree requires --format human");
        return ExitCode::FAILURE;
    }
    if let Some(dir) = &args.dump {
        if !args.force && is_nonempty_dir(dir) {
            eprintln!(
                "Error: {} is not empty; use --force to write into it",
                dir.display()
            );
            return ExitCode::FAILURE;
        }
    }
    let mut success = true;
    for (index, path) in args.files.iter().enumerate() {
        if let Err(e) = certs_file(path, index + 1, args) {
            eprintln!("Error scanning {}: {e}", path.display());
            success = false;
        }
    }
    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// One input's strings, for JSON output.
#[derive(serde::Serialize)]
struct StringsFile<'a> {
    file: String,
    strings: &'a [zrax::strings::FoundString],
}

fn strings_file(
    path: &std::path::Path,
    options: &zrax::strings::Options,
    args: &StringsArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = std::fs::read(path)?;
    let mut strings = zrax::strings::extract(&data, options, usize::MAX).strings;
    if !args.tags.is_empty() {
        let wanted = args
            .tags
            .iter()
            .fold(zrax::strings::Tags::empty(), |all, tag| all | *tag);
        strings.retain(|found| found.tags.intersects(wanted));
    }
    match args.format {
        StringsFormat::Text => {
            let radix = args.radix.map(|radix| match radix {
                Radix::Octal => zrax::formatter::OffsetRadix::Octal,
                Radix::Decimal => zrax::formatter::OffsetRadix::Decimal,
                Radix::Hex => zrax::formatter::OffsetRadix::Hex,
            });
            let text = zrax::formatter::strings_text(&strings, radix);
            if args.files.len() > 1 {
                for line in text.lines() {
                    println!("{}: {line}", path.display());
                }
            } else {
                print!("{text}");
            }
        }
        StringsFormat::Csv => print!("{}", zrax::formatter::strings_csv(&strings)),
        StringsFormat::Json => {
            let output = StringsFile {
                file: path.display().to_string(),
                strings: &strings,
            };
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
    }
    Ok(())
}

fn run_strings(args: &StringsArgs) -> ExitCode {
    let encodings = args
        .encodings
        .iter()
        .fold(zrax::strings::Encodings::empty(), |all, encoding| {
            all | encoding.flag()
        });
    let options = match zrax::strings::Options::new(args.min_len, encodings) {
        Ok(options) => options,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut success = true;
    for path in &args.files {
        if let Err(e) = strings_file(path, &options, args) {
            eprintln!("Error scanning {}: {e}", path.display());
            success = false;
        }
    }
    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

// ---------------------------------------------------------------------------
// Default classify mode (unchanged from original)
// ---------------------------------------------------------------------------

/// Build classifier options from CLI args.
fn build_options(cli: &Cli) -> ClassifierOptions {
    match cli.mode {
        AnalysisMode::Normal => {
            let mut opts = ClassifierOptions::new();
            opts.min_confidence = cli.min_confidence;
            opts.detect_extensions = cli.extensions;
            opts
        }
        AnalysisMode::Fast => {
            let mut opts = ClassifierOptions::fast();
            opts.min_confidence = cli.min_confidence.max(opts.min_confidence);
            opts.detect_extensions = cli.extensions;
            opts
        }
        AnalysisMode::Thorough => {
            let mut opts = ClassifierOptions::thorough();
            opts.min_confidence = cli.min_confidence.min(opts.min_confidence);
            opts.detect_extensions = true;
            opts
        }
    }
}

/// Analyze a single file and output results using the appropriate formatter.
fn analyze_file(
    path: &PathBuf,
    options: &ClassifierOptions,
    cli: &Cli,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = std::fs::read(path)?;
    let payload = detect_payload(&data, options)?;
    let output = format_output(&payload, path, cli);
    print!("{}", output);

    if cli.candidates && !payload.candidates.is_empty() {
        let candidates_formatter = CandidatesFormatter::new();
        print!("{}", candidates_formatter.format_payload(&payload, path));
    }

    Ok(())
}

/// Analyze the input files as byte lanes of one interleaved image.
fn analyze_interleaved(
    options: &ClassifierOptions,
    cli: &Cli,
) -> Result<(), Box<dyn std::error::Error>> {
    let lanes = cli
        .files
        .iter()
        .map(std::fs::read)
        .collect::<Result<Vec<_>, _>>()?;
    let views: Vec<&[u8]> = lanes.iter().map(Vec::as_slice).collect();
    let payload = detect_interleaved(&views, options)?;
    print!("{}", format_output(&payload, &cli.files[0], cli));
    Ok(())
}

/// Analyze a file for multiple ISAs using windowed detection.
fn analyze_multi_isa(path: &PathBuf, cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let data = std::fs::read(path)?;
    let detected = detect_multi_isa(&data, cli.window_size);

    match cli.format {
        OutputFormat::Json => {
            #[derive(serde::Serialize)]
            struct MultiIsaOutput {
                file: String,
                multi_isa: bool,
                detected_isas: Vec<IsaEntry>,
                primary_isa: Option<String>,
            }

            #[derive(serde::Serialize)]
            struct IsaEntry {
                isa: String,
                bitwidth: u8,
                endianness: String,
                window_count: usize,
                total_bytes: usize,
                avg_score: f64,
            }

            let primary = detected.first().map(|d| d.isa.to_string());
            let entries: Vec<IsaEntry> = detected
                .iter()
                .map(|d| IsaEntry {
                    isa: d.isa.to_string(),
                    bitwidth: d.bitwidth,
                    endianness: d.endianness.to_string(),
                    window_count: d.window_count,
                    total_bytes: d.total_bytes,
                    avg_score: d.avg_score,
                })
                .collect();

            let output = MultiIsaOutput {
                file: path.display().to_string(),
                multi_isa: entries.len() > 1,
                detected_isas: entries,
                primary_isa: primary,
            };

            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        OutputFormat::Human => {
            println!("File: {}", path.display());
            if detected.is_empty() {
                println!("  No ISAs detected");
            } else {
                println!("  Detected {} ISA(s):", detected.len());
                for d in &detected {
                    println!(
                        "    {:<12} {:>3} windows, {:>6} bytes, avg_score {:.1}",
                        d.isa.to_string(),
                        d.window_count,
                        d.total_bytes,
                        d.avg_score,
                    );
                }
            }
        }
        OutputFormat::Short => {
            let isas: Vec<String> = detected.iter().map(|d| d.isa.to_string()).collect();
            println!("{}: {}", path.display(), isas.join("+"));
        }
    }

    Ok(())
}

/// Format the payload using the appropriate formatter.
fn format_output(payload: &DetectionPayload, path: &PathBuf, cli: &Cli) -> String {
    match cli.format {
        OutputFormat::Human => {
            let formatter = if cli.quiet {
                HumanFormatter::quiet()
            } else if cli.verbose {
                HumanFormatter::verbose()
            } else {
                HumanFormatter::new()
            };
            formatter.format_payload(payload, path)
        }
        OutputFormat::Json => {
            let formatter = JsonFormatter::new();
            formatter.format_payload(payload, path)
        }
        OutputFormat::Short => {
            let formatter = ShortFormatter::new();
            formatter.format_payload(payload, path)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_parsing() {
        let cli = Cli::try_parse_from(["zrax", "test.bin"]).unwrap();
        assert_eq!(cli.files.len(), 1);
        assert!(!cli.verbose);
        assert!(!cli.multi_isa);
    }

    #[test]
    fn test_multiple_files() {
        let cli = Cli::try_parse_from(["zrax", "a.bin", "b.bin"]).unwrap();
        assert_eq!(cli.files.len(), 2);
    }

    #[test]
    fn test_format_options() {
        let cli = Cli::try_parse_from(["zrax", "-f", "json", "test.bin"]).unwrap();
        assert!(matches!(cli.format, OutputFormat::Json));
    }

    #[test]
    fn test_multi_isa_flag() {
        let cli = Cli::try_parse_from(["zrax", "--multi-isa", "test.bin"]).unwrap();
        assert!(cli.multi_isa);
        assert_eq!(cli.window_size, 1024);
    }

    #[test]
    fn certs_and_strings_subcommands_parse_their_options() {
        let cli =
            Cli::try_parse_from(["zrax", "certs", "--dump", "out", "--der", "a.bin"]).unwrap();
        let Some(Commands::Certs(args)) = cli.command else {
            panic!("certs subcommand expected");
        };
        assert!(args.der && !args.pem);
        assert_eq!(args.files, vec![PathBuf::from("a.bin")]);
        assert!(Cli::try_parse_from(["zrax", "certs", "--der", "a.bin"]).is_err());

        let cli = Cli::try_parse_from([
            "zrax", "strings", "-n", "6", "-e", "utf16be", "-t", "x", "a",
        ])
        .unwrap();
        let Some(Commands::Strings(args)) = cli.command else {
            panic!("strings subcommand expected");
        };
        assert_eq!(args.min_len, 6);
        assert_eq!(args.encodings, vec![zrax::strings::Encoding::Utf16be]);
        assert_eq!(args.radix, Some(Radix::Hex));
        assert!(Cli::try_parse_from(["zrax", "strings", "-e", "ebcdic", "a"]).is_err());
        assert!(Cli::try_parse_from(["zrax", "strings", "--tag", "nope", "a"]).is_err());
    }

    #[test]
    fn test_window_size() {
        let cli = Cli::try_parse_from([
            "zrax",
            "--multi-isa",
            "--window-size",
            "2048",
            "test.bin",
        ])
        .unwrap();
        assert_eq!(cli.window_size, 2048);
    }
}
