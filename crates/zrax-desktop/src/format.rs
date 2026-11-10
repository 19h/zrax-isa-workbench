//! Text formatting shared by every view: sizes, offsets, numbers and the
//! small enumerations of a payload.
//!
//! These follow `web/format.js` and `web/hex-utils.js` so both workbenches
//! print the same text for the same value. Sizes use binary units.

use zrax::types::{
    ClassificationSource, Endianness, MetadataEntry, MetadataKey, MetadataValue, Variant,
};

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

/// `n / unit` with `decimals` (1 or 2) fraction digits, rounded half up as
/// JavaScript's `toFixed` rounds a positive value.
fn fixed(n: u64, unit: u64, decimals: u32) -> String {
    let scale = 10u64.pow(decimals);
    let scaled =
        (u128::from(n) * u128::from(scale) * 2 + u128::from(unit)) / (u128::from(unit) * 2);
    let whole = scaled / u128::from(scale);
    let fraction = scaled % u128::from(scale);
    format!("{whole}.{fraction:0width$}", width = decimals as usize)
}

/// `512 B`, `70.4 KiB`, `1.50 MiB`, `2.00 GiB`.
pub fn size(bytes: u64) -> String {
    if bytes < KIB {
        format!("{bytes} B")
    } else if bytes < MIB {
        format!("{} KiB", fixed(bytes, KIB, 1))
    } else if bytes < GIB {
        format!("{} MiB", fixed(bytes, MIB, 2))
    } else {
        format!("{} GiB", fixed(bytes, GIB, 2))
    }
}

/// Uppercase hexadecimal, zero-padded to `width` digits, without a prefix.
pub fn hex(value: u64, width: usize) -> String {
    format!("{value:0width$X}")
}

/// `0x` plus eight or more uppercase digits: a file offset.
pub fn offset(value: u64) -> String {
    format!("0x{}", hex(value, 8))
}

/// A decimal count with `,` between groups of three digits (`72,080`).
pub fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut text = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            text.push(',');
        }
        text.push(digit);
    }
    text
}

/// A fraction as a percentage with one decimal (`99.0%`).
pub fn percent(fraction: f64) -> String {
    format!("{:.1}%", fraction * 100.0)
}

/// `Little-endian`, `Big-endian` or `Bi-endian`.
pub fn endianness(endianness: Endianness) -> &'static str {
    match endianness {
        Endianness::Little => "Little-endian",
        Endianness::Big => "Big-endian",
        Endianness::BiEndian => "Bi-endian",
    }
}

/// The byte-order word for compact rows: `little`, `big` or `bi-endian`.
pub fn endianness_short(endianness: Endianness) -> &'static str {
    match endianness {
        Endianness::Little => "little",
        Endianness::Big => "big",
        Endianness::BiEndian => "bi-endian",
    }
}

/// How a classification was reached, capitalized.
pub fn source(source: ClassificationSource) -> &'static str {
    match source {
        ClassificationSource::FileFormat => "File format",
        ClassificationSource::Heuristic => "Heuristic",
        ClassificationSource::Combined => "Combined",
        ClassificationSource::UserSpecified => "User specified",
    }
}

/// `name / profile [abi]`, with the parts the variant has.
pub fn variant(variant: &Variant) -> String {
    let mut text = variant.name.clone();
    if let Some(profile) = &variant.profile {
        text.push_str(" / ");
        text.push_str(profile);
    }
    if let Some(abi) = &variant.abi {
        text.push_str(" [");
        text.push_str(abi);
        text.push(']');
    }
    text
}

/// A metadata value as the browser prints it: entry points, flags and raw
/// machine values in hex, other numbers grouped, text as it is.
pub fn metadata_value(entry: &MetadataEntry) -> String {
    let number = match &entry.value {
        MetadataValue::String(text) => return text.clone(),
        MetadataValue::Address(value) | MetadataValue::Integer(value) => *value,
        MetadataValue::Hex(value) => u64::from(*value),
    };
    let is_hex_key = matches!(
        entry.key,
        MetadataKey::EntryPoint | MetadataKey::Flags | MetadataKey::RawMachine
    );
    if is_hex_key {
        format!("0x{number:X}")
    } else {
        grouped(number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_use_binary_units_and_round_half_up() {
        assert_eq!(size(0), "0 B");
        assert_eq!(size(1023), "1023 B");
        assert_eq!(size(1024), "1.0 KiB");
        assert_eq!(size(72_080), "70.4 KiB");
        // 1280 B is exactly 1.25 KiB; `toFixed(1)` prints 1.3.
        assert_eq!(size(1280), "1.3 KiB");
        assert_eq!(size(3 * MIB / 2), "1.50 MiB");
        assert_eq!(size(2 * GIB), "2.00 GiB");
    }

    #[test]
    fn offsets_and_counts() {
        assert_eq!(hex(0x1A, 2), "1A");
        assert_eq!(offset(0), "0x00000000");
        assert_eq!(offset(0x1_2345_6789), "0x123456789");
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(72_080), "72,080");
        assert_eq!(grouped(1_000_000), "1,000,000");
        assert_eq!(percent(0.99), "99.0%");
    }

    #[test]
    fn metadata_numbers_are_hex_only_for_address_like_keys() {
        let entry = |key, value| MetadataEntry {
            key,
            value,
            label: String::new(),
        };
        let entry_point = entry(MetadataKey::EntryPoint, MetadataValue::Address(0x8000));
        assert_eq!(metadata_value(&entry_point), "0x8000");
        let sections = entry(MetadataKey::SectionCount, MetadataValue::Integer(72_080));
        assert_eq!(metadata_value(&sections), "72,080");
        let custom = entry(
            MetadataKey::Custom("usb_vendor_id".into()),
            MetadataValue::String("0x1FC9".into()),
        );
        assert_eq!(metadata_value(&custom), "0x1FC9");
    }

    #[test]
    fn variants_list_profile_and_abi() {
        assert_eq!(variant(&Variant::new("thumb")), "thumb");
        assert_eq!(variant(&Variant::with_profile("v7", "M")), "v7 / M");
        assert_eq!(variant(&Variant::with_abi("v8", "ilp32")), "v8 [ilp32]");
    }
}
