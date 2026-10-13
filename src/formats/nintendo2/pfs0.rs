//! Switch `PFS0` archives: NSP packages (nstool `README.md` lists the
//! Nintendo Submission Package among the `PartitionFs` formats; hactool
//! reads them with `--intype=pfs0`) and `ExeFS` images, whose `main.npdm`
//! carries the `META` magic (hactool `pfs0_process`).
//!
//! The table layout is in [`partition_fs`]. Every file is a child labeled
//! by its name. NCAs are AES-XTS encrypted (switchbrew "NCA"), tickets and
//! certificates are data, so they are opaque unless their bytes are a
//! recognized format; NSO and NRO files are classified by `console.rs`.

use super::partition_fs::{self, Kind};
use super::*;

/// Prefix of this layout's metadata keys.
const KEY_PREFIX: &str = "pfs0";

/// The `ExeFS` program metadata file and its magic (hactool
/// `MAGIC_META`).
const NPDM_NAME: &str = "main.npdm";
const NPDM_MAGIC: &[u8; 4] = b"META";

/// Strong recognition: `PFS0` at 0 with an entry table and string table
/// that fit in the file.
pub(super) fn detect(data: &[u8]) -> bool {
    partition_fs::has_header(data, 0, Kind::Pfs0)
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let fs = partition_fs::parse(data, 0, data.len(), Kind::Pfs0)?;
    let trailing = &data[fs.end..];
    if !is_padding(trailing) {
        return Err(error(format!(
            "Unexpected {} after the PFS0 data at 0x{:X}",
            size_text(trailing.len()),
            fs.end
        )));
    }
    let mut c = Container::new(FileFormat::Pfs0, Layout::Pfs0.label(), KEY_PREFIX);
    c.consumed = data.len();
    c.notes.push(format!(
        "PFS0: {}; header and string table {}; the container names no CPU",
        counted(fs.entry_count, "file", "files"),
        size_text(fs.header_size)
    ));
    let is_exefs = fs
        .files
        .iter()
        .any(|file| file.name == NPDM_NAME && file.region.bytes(data).starts_with(NPDM_MAGIC));
    if is_exefs {
        c.notes.push(
            "main.npdm carries the META magic, which hactool takes as the mark of an ExeFS"
                .to_string(),
        );
    }
    c.push_metadata(
        format!("{KEY_PREFIX}_files"),
        "Files",
        fs.entry_count as u64,
    );
    let mut members = Members::new(data.len());
    for file in &fs.files {
        members.offer(
            file.name.clone(),
            file.region.offset,
            file.region.bytes(data),
        );
    }
    let unlisted = fs.entry_count - fs.files.len();
    members.finish(&mut c, "file", "files");
    if unlisted > 0 {
        c.notes.push(format!(
            "Member limit reached ({MAX_COMPONENTS} members); not listed: {}",
            counted(unlisted, "further file", "further files")
        ));
    }
    Ok(c)
}
