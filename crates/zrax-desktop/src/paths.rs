//! Turning what the user dropped or picked into a list of files.
//!
//! A folder stands for every regular file below it. Symbolic links inside a
//! folder are not followed: a link can point outside the folder the user
//! chose, or back into it.

use std::path::{Path, PathBuf};

/// Most files one drop or pick adds. A folder with more is cut off and the
/// session log says so.
pub const MAX_FILES_PER_ADD: usize = 20_000;

/// The files of one drop or pick.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Expanded {
    /// Regular files, in the order given; a folder's files sorted by path.
    pub files: Vec<PathBuf>,
    /// Whether [`MAX_FILES_PER_ADD`] cut the list short.
    pub is_truncated: bool,
}

/// Expand `picked` into files. A path the user named directly is taken as
/// it is, even when it is a symbolic link; unreadable folders are skipped.
pub fn expand(picked: &[PathBuf]) -> Expanded {
    let mut expanded = Expanded::default();
    for path in picked {
        if path.is_dir() {
            collect_files(path, &mut expanded);
        } else {
            push(path.clone(), &mut expanded);
        }
    }
    expanded
}

fn push(file: PathBuf, expanded: &mut Expanded) {
    if expanded.files.len() < MAX_FILES_PER_ADD {
        expanded.files.push(file);
    } else {
        expanded.is_truncated = true;
    }
}

/// Add every regular file below `directory`, depth first, in path order.
/// Iterative, so a deep tree cannot exhaust the stack.
fn collect_files(directory: &Path, expanded: &mut Expanded) {
    let mut pending = vec![directory.to_path_buf()];
    while let Some(current) = pending.pop() {
        if expanded.is_truncated {
            return;
        }
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        let mut children: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        children.sort();
        let mut subdirectories = Vec::new();
        for child in children {
            // `symlink_metadata` describes the link itself, not its target.
            let Ok(metadata) = std::fs::symlink_metadata(&child) else {
                continue;
            };
            if metadata.is_file() {
                push(child, expanded);
            } else if metadata.is_dir() {
                subdirectories.push(child);
            }
        }
        // Popped last-in first-out: reverse to visit in path order.
        pending.extend(subdirectories.into_iter().rev());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique scratch directory under the crate's target directory, so
    /// tests leave nothing outside the repository.
    fn scratch(name: &str) -> PathBuf {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../target/test-scratch")
            .join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn folders_expand_to_their_files_in_path_order() {
        let root = scratch("expand-order");
        std::fs::create_dir_all(root.join("b/inner")).unwrap();
        std::fs::write(root.join("b/inner/z.bin"), b"z").unwrap();
        std::fs::write(root.join("b/y.bin"), b"y").unwrap();
        std::fs::write(root.join("a.bin"), b"a").unwrap();
        let single = root.join("a.bin");

        let expanded = expand(&[root.clone(), single.clone()]);

        let expected = vec![
            root.join("a.bin"),
            root.join("b/y.bin"),
            root.join("b/inner/z.bin"),
            single,
        ];
        assert_eq!(expanded.files, expected);
        assert!(!expanded.is_truncated);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn links_inside_a_folder_are_not_followed() {
        let root = scratch("expand-links");
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::fs::write(root.join("real/file.bin"), b"x").unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("loop")).unwrap();
        std::os::unix::fs::symlink(root.join("real/file.bin"), root.join("alias.bin")).unwrap();

        let expanded = expand(std::slice::from_ref(&root));

        assert_eq!(expanded.files, vec![root.join("real/file.bin")]);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_missing_path_is_passed_through_for_analysis_to_report() {
        let missing = PathBuf::from("/nonexistent/zrax-desktop-test.bin");
        assert_eq!(expand(std::slice::from_ref(&missing)).files, vec![missing]);
    }
}
