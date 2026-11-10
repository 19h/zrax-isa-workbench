//! The analysis pass over one file: read, classify, profile, enumerate.
//!
//! Runs on a background thread. Input is untrusted, and although the
//! classifier's parsers are written not to panic, a panic here must cost
//! one file, not the application, so the pass is isolated with
//! `catch_unwind`.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use std::time::Instant;

use zrax::workbench::Engine;

use crate::model::entry::{Analysis, Source};

/// Bins of the entropy profile shown in strips and list rows.
pub const PROFILE_POINTS: usize = 1024;

/// Largest file kept resident for inspection, as in the browser workbench.
pub const MAX_RESIDENT_BYTES: u64 = 1024 * 1024 * 1024;

/// What to analyze.
#[derive(Debug, Clone)]
pub struct Request {
    /// Where the bytes come from.
    pub source: Source,
    /// Inspect bytes only; do not run the classifier.
    pub opaque: bool,
}

/// Read the source and analyze it.
///
/// # Errors
///
/// A user-facing message when the file cannot be read, exceeds
/// [`MAX_RESIDENT_BYTES`], or analysis crashed.
pub fn run(request: &Request) -> Result<Analysis, String> {
    let data = read(&request.source)?;
    catch_unwind(AssertUnwindSafe(|| analyze(data, request.opaque)))
        .map_err(|_| "Analysis crashed on this file".to_string())
}

fn read(source: &Source) -> Result<Arc<[u8]>, String> {
    match source {
        Source::Memory(data) => Ok(data.clone()),
        Source::File(path) => {
            let metadata =
                std::fs::metadata(path).map_err(|error| format!("Read failed: {error}"))?;
            if metadata.len() > MAX_RESIDENT_BYTES {
                return Err(format!(
                    "Unsupported file size {}; the limit is {}",
                    crate::format::size(metadata.len()),
                    crate::format::size(MAX_RESIDENT_BYTES)
                ));
            }
            let data = std::fs::read(path).map_err(|error| format!("Read failed: {error}"))?;
            Ok(Arc::from(data))
        }
    }
}

fn analyze(data: Arc<[u8]>, opaque: bool) -> Analysis {
    let started = Instant::now();
    let engine = if opaque {
        Engine::opaque(data)
    } else {
        Engine::new(data)
    };
    let (payload, error) = match engine.classification() {
        Ok(payload) => (payload, None),
        Err(error) => (None, Some(error.to_string())),
    };
    let profile: Arc<[f32]> = if engine.data().is_empty() {
        Arc::from([])
    } else {
        Arc::from(engine.profile(PROFILE_POINTS))
    };
    let mean_entropy = mean(&profile);
    let (subfiles, subfile_error) = match engine.subfiles() {
        Ok(subfiles) => (subfiles, None),
        Err(error) => (Vec::new(), Some(error.to_string())),
    };
    Analysis {
        engine,
        payload,
        error,
        profile,
        mean_entropy,
        subfiles,
        subfile_error,
        elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
    }
}

fn mean(profile: &[f32]) -> Option<f32> {
    if profile.is_empty() {
        return None;
    }
    // At most PROFILE_POINTS values, so the count is exact in f32.
    #[allow(clippy::cast_precision_loss)]
    let count = profile.len() as f32;
    Some(profile.iter().sum::<f32>() / count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory(bytes: &[u8], opaque: bool) -> Request {
        Request {
            source: Source::Memory(Arc::from(bytes)),
            opaque,
        }
    }

    #[test]
    fn an_unrecognized_file_still_gets_a_profile_and_an_error_message() {
        let analysis = run(&memory(&[0u8; 8192], false)).unwrap();
        assert!(analysis.payload.is_none());
        assert!(analysis.error.is_some());
        assert_eq!(analysis.profile.len(), PROFILE_POINTS);
        assert_eq!(analysis.mean_entropy, Some(0.0));
    }

    #[test]
    fn an_opaque_component_is_profiled_but_not_classified() {
        let analysis = run(&memory(&[1, 2, 3, 4], true)).unwrap();
        assert!(analysis.payload.is_none() && analysis.error.is_none());
        assert_eq!(analysis.profile.len(), 4);
    }

    #[test]
    fn an_empty_file_has_no_profile_and_no_mean() {
        let analysis = run(&memory(&[], false)).unwrap();
        assert!(analysis.profile.is_empty());
        assert_eq!(analysis.mean_entropy, None);
    }

    #[test]
    fn a_missing_file_reports_the_read_error() {
        let request = Request {
            source: Source::File("/nonexistent/zrax-desktop-test".into()),
            opaque: false,
        };
        assert!(run(&request).unwrap_err().starts_with("Read failed: "));
    }
}
