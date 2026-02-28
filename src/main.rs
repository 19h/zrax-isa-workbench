//! ISA Classifier CLI
//!
//! Command-line tool for identifying processor architectures in binary files.

use clap::{Parser, ValueEnum};
use isa_classifier::{
    detect_multi_isa, detect_payload, CandidatesFormatter, ClassifierOptions, DetectionPayload,
    HumanFormatter, JsonFormatter, PayloadFormatter, ShortFormatter,
};
use std::path::PathBuf;
use std::process::ExitCode;

/// Universal binary architecture classifier.
///
/// Identifies processor architectures, ISA variants, and extensions
/// from ELF, PE, Mach-O, and raw binary files.
#[derive(Parser, Debug)]
#[command(name = "isa-classify")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Input file(s) to analyze
    #[arg(required = true)]
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
    let args = Args::parse();

    // Initialize logging if verbose
    if args.verbose {
        tracing_subscriber::fmt()
            .with_env_filter("isa_classifier=debug")
            .init();
    }

    let options = build_options(&args);
    let mut success = true;

    for path in &args.files {
        if args.multi_isa {
            match analyze_multi_isa(path, &args) {
                Ok(()) => {}
                Err(e) => {
                    if !args.quiet {
                        eprintln!("Error analyzing {}: {}", path.display(), e);
                    }
                    success = false;
                }
            }
        } else {
            match analyze_file(path, &options, &args) {
                Ok(()) => {}
                Err(e) => {
                    if !args.quiet {
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

/// Build classifier options from CLI args.
fn build_options(args: &Args) -> ClassifierOptions {
    match args.mode {
        AnalysisMode::Normal => {
            let mut opts = ClassifierOptions::new();
            opts.min_confidence = args.min_confidence;
            opts.detect_extensions = args.extensions;
            opts
        }
        AnalysisMode::Fast => {
            let mut opts = ClassifierOptions::fast();
            opts.min_confidence = args.min_confidence.max(opts.min_confidence);
            opts.detect_extensions = args.extensions;
            opts
        }
        AnalysisMode::Thorough => {
            let mut opts = ClassifierOptions::thorough();
            opts.min_confidence = args.min_confidence.min(opts.min_confidence);
            opts.detect_extensions = true;
            opts
        }
    }
}

/// Analyze a single file and output results using the appropriate formatter.
fn analyze_file(
    path: &PathBuf,
    options: &ClassifierOptions,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read file and detect
    let data = std::fs::read(path)?;
    let payload = detect_payload(&data, options)?;

    // Select formatter based on output format and options
    let output = format_output(&payload, path, args);
    print!("{}", output);

    // Print candidates if requested (separate from main output)
    if args.candidates && !payload.candidates.is_empty() {
        let candidates_formatter = CandidatesFormatter::new();
        print!("{}", candidates_formatter.format_payload(&payload, path));
    }

    Ok(())
}

/// Analyze a file for multiple ISAs using windowed detection.
fn analyze_multi_isa(path: &PathBuf, args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let data = std::fs::read(path)?;
    let detected = detect_multi_isa(&data, args.window_size);

    match args.format {
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
fn format_output(payload: &DetectionPayload, path: &PathBuf, args: &Args) -> String {
    match args.format {
        OutputFormat::Human => {
            let formatter = if args.quiet {
                HumanFormatter::quiet()
            } else if args.verbose {
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
        let args = Args::try_parse_from(["isa-classify", "test.bin"]).unwrap();
        assert_eq!(args.files.len(), 1);
        assert!(!args.verbose);
        assert!(!args.multi_isa);
    }

    #[test]
    fn test_multiple_files() {
        let args = Args::try_parse_from(["isa-classify", "a.bin", "b.bin"]).unwrap();
        assert_eq!(args.files.len(), 2);
    }

    #[test]
    fn test_format_options() {
        let args = Args::try_parse_from(["isa-classify", "-f", "json", "test.bin"]).unwrap();
        assert!(matches!(args.format, OutputFormat::Json));
    }

    #[test]
    fn test_multi_isa_flag() {
        let args = Args::try_parse_from(["isa-classify", "--multi-isa", "test.bin"]).unwrap();
        assert!(args.multi_isa);
        assert_eq!(args.window_size, 1024);
    }

    #[test]
    fn test_window_size() {
        let args = Args::try_parse_from([
            "isa-classify",
            "--multi-isa",
            "--window-size",
            "2048",
            "test.bin",
        ])
        .unwrap();
        assert_eq!(args.window_size, 2048);
    }
}
