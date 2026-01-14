//! ISA Classifier CLI
//!
//! Command-line tool for identifying processor architectures in binary files.

use clap::{Parser, ValueEnum};
use isa_classifier::{
    classify_bytes_with_options, ClassificationResult, ClassifierOptions,
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

    let options = match args.mode {
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
    };

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

fn analyze_file(
    path: &PathBuf,
    options: &ClassifierOptions,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = std::fs::read(path)?;
    let result = classify_bytes_with_options(&data, options)?;

    match args.format {
        OutputFormat::Human => print_human(&result, path, args),
        OutputFormat::Json => print_json(&result, path)?,
        OutputFormat::Short => print_short(&result, path),
    }

    if args.candidates {
        print_candidates(&data, options);
    }

    Ok(())
}

fn print_human(result: &ClassificationResult, path: &PathBuf, args: &Args) {
    if args.quiet {
        println!("{}: {}", path.display(), result.isa);
        return;
    }

    println!("File: {}", path.display());
    println!("  ISA:        {} ({})", result.isa, result.isa.name());
    println!("  Bitwidth:   {}-bit", result.bitwidth);
    println!("  Endianness: {}", result.endianness);
    println!("  Format:     {}", result.format);
    println!("  Confidence: {:.1}%", result.confidence * 100.0);

    if !result.variant.name.is_empty() {
        println!("  Variant:    {}", result.variant);
    }

    if !result.extensions.is_empty() {
        print!("  Extensions: ");
        let ext_names: Vec<_> = result.extensions.iter().map(|e| e.name.as_str()).collect();
        println!("{}", ext_names.join(", "));
    }

    if args.verbose {
        println!("  Source:     {:?}", result.source);
        if let Some(entry) = result.metadata.entry_point {
            println!("  Entry:      0x{:X}", entry);
        }
        if let Some(machine) = result.metadata.raw_machine {
            println!("  Machine:    0x{:04X} ({})", machine, machine);
        }
        if let Some(flags) = result.metadata.flags {
            println!("  Flags:      0x{:08X}", flags);
        }
    }

    println!();
}

fn print_json(
    result: &ClassificationResult,
    path: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    #[derive(serde::Serialize)]
    struct JsonOutput {
        file: String,
        isa: String,
        isa_name: &'static str,
        bitwidth: u8,
        endianness: String,
        format: String,
        confidence: f64,
        variant: Option<String>,
        extensions: Vec<String>,
        entry_point: Option<String>,
        raw_machine: Option<u32>,
        flags: Option<u32>,
    }

    let output = JsonOutput {
        file: path.display().to_string(),
        isa: result.isa.to_string(),
        isa_name: result.isa.name(),
        bitwidth: result.bitwidth,
        endianness: result.endianness.to_string(),
        format: result.format.to_string(),
        confidence: result.confidence,
        variant: if result.variant.name.is_empty() {
            None
        } else {
            Some(result.variant.to_string())
        },
        extensions: result.extensions.iter().map(|e| e.name.clone()).collect(),
        entry_point: result.metadata.entry_point.map(|e| format!("0x{:X}", e)),
        raw_machine: result.metadata.raw_machine,
        flags: result.metadata.flags,
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn print_short(result: &ClassificationResult, path: &PathBuf) {
    let exts = if result.extensions.is_empty() {
        String::new()
    } else {
        let names: Vec<_> = result.extensions.iter().map(|e| e.name.as_str()).collect();
        format!(" [{}]", names.join(","))
    };

    println!(
        "{}\t{}\t{}\t{}\t{:.0}%{}",
        path.display(),
        result.isa,
        result.bitwidth,
        result.endianness,
        result.confidence * 100.0,
        exts
    );
}

fn print_candidates(data: &[u8], options: &ClassifierOptions) {
    let candidates = isa_classifier::heuristics::top_candidates(data, 5, options);

    println!("Top candidates:");
    for (i, candidate) in candidates.iter().enumerate() {
        println!(
            "  {}. {} ({}-bit, {}) - score: {}, confidence: {:.1}%",
            i + 1,
            candidate.isa,
            candidate.bitwidth,
            candidate.endianness,
            candidate.raw_score,
            candidate.confidence * 100.0
        );
    }
    println!();
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
