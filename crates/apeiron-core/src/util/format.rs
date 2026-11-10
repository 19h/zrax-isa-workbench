//! Formatting utility functions.
//!
//! Provides human-readable formatting for various data types.

/// Format byte count as human-readable string.
///
/// # Examples
/// ```
/// use apeiron::util::format::format_bytes;
/// assert_eq!(format_bytes(1024), "1.00 KB");
/// assert_eq!(format_bytes(1048576), "1.00 MB");
/// ```
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format a hex dump string for a data chunk.
///
/// Format: `XXXXXXXX  XX XX XX XX XX XX XX XX  XX XX XX XX XX XX XX XX  |................|`
#[allow(dead_code)]
pub fn hex_dump(data: &[u8], start_offset: usize) -> String {
    use std::fmt::Write;

    const BYTES_PER_LINE: usize = 16;

    let mut output = String::with_capacity(data.len() * 4);
    let lines = (data.len() + BYTES_PER_LINE - 1) / BYTES_PER_LINE;

    for i in 0..lines {
        let offset = i * BYTES_PER_LINE;
        let end = (offset + BYTES_PER_LINE).min(data.len());
        let chunk = &data[offset..end];

        // Address
        let _ = write!(output, "{:08X}  ", start_offset + offset);

        // Hex bytes (lowercase for traditional hex dump style)
        for (idx, &byte) in chunk.iter().enumerate() {
            let _ = write!(output, "{byte:02x} ");
            if idx == 7 {
                output.push(' ');
            }
        }

        // Padding for incomplete lines
        let remaining = BYTES_PER_LINE - chunk.len();
        if remaining > 0 {
            for _ in 0..remaining {
                output.push_str("   ");
            }
            if chunk.len() <= 8 {
                output.push(' ');
            }
        }

        output.push_str(" |");

        // ASCII representation
        for &byte in chunk {
            if byte >= 32 && byte <= 126 {
                output.push(byte as char);
            } else {
                output.push('.');
            }
        }

        output.push_str("|\n");
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
        assert_eq!(format_bytes(1073741824), "1.00 GB");
        assert_eq!(format_bytes(1099511627776), "1.00 TB");
    }

    #[test]
    fn test_hex_dump() {
        let data = [0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello"
        let dump = hex_dump(&data, 0);
        assert!(dump.contains("48 65 6c 6c 6f"));
        assert!(dump.contains("|Hello"));
    }
}
