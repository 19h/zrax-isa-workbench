//! ISA Classifier CLI
//!
//! Command-line tool for identifying processor architectures in binary files.

use clap::{Parser, ValueEnum};
use isa_classifier::{
    detect_payload, ClassifierOptions, DetectionPayload, HumanFormatter, JsonFormatter,
    PayloadFormatter, ShortFormatter, CandidatesFormatter,
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
}
