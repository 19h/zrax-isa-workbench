//! Labelled stored ranges: executable sections, Mach-O slices and segments,
//! PE attribute certificates, Image4 manifests and container members, and
//! how certificates found by scanning are placed in them.

use zrax::certificates;
use zrax::formats::compressed::{self, Codec};
use zrax::inspection::{enclosing, regions, Region, RegionKind};

const LEAF: &[u8] = include_bytes!("fixtures/certificates/leaf.der");
const ROOT: &[u8] = include_bytes!("fixtures/certificates/root.der");
const INTERMEDIATE: &[u8] = include_bytes!("fixtures/certificates/intermediate.der");
const IM4M: &[u8] = include_bytes!("fixtures/apple/synthetic.im4m");
const IMG4: &[u8] = include_bytes!("fixtures/apple/krnl.img4");
const TAR: &[u8] = include_bytes!("fixtures/archives/gnu.tar");

/// ELF section types and PE constants used by the builders.
const SHT_PROGBITS: u32 = 1;
const SHT_STRTAB: u32 = 3;
const SHT_NOBITS: u32 = 8;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const PE32PLUS_MAGIC: u16 = 0x20b;
const WIN_CERT_REVISION_2_0: u16 = 0x0200;
const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 2;
const FAT_MAGIC: u32 = 0xcafe_babe;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;

fn gunzip(name: &str) -> Vec<u8> {
    let stored = std::fs::read(format!("tests/fixtures/macho/{name}")).unwrap();
    compressed::decode(Codec::Gzip, &stored).unwrap().data
}

fn labels(regions: &[Region]) -> Vec<&str> {
    regions.iter().map(|r| r.label.as_str()).collect()
}

fn find<'a>(regions: &'a [Region], label: &str) -> &'a Region {
    regions
        .iter()
        .find(|r| r.label == label)
        .unwrap_or_else(|| panic!("{label:?} in {:?}", labels(regions)))
}

fn put(data: &mut [u8], at: usize, bytes: &[u8]) {
    data[at..at + bytes.len()].copy_from_slice(bytes);
}

/// ELF64 little-endian relocatable file: 64 B header, `.text` (16 B of
/// code at 0x100), `.bss` (no file bytes), `.shstrtab` at 0x120, then the
/// four section headers (null first) at 0x140.
fn elf64() -> Vec<u8> {
    let names = b"\0.text\0.bss\0.shstrtab\0";
    let mut data = vec![0u8; 0x140 + 4 * 64];
    put(&mut data, 0, b"\x7fELF\x02\x01\x01");
    put(&mut data, 0x10, &1u16.to_le_bytes()); // e_type ET_REL
    put(&mut data, 0x12, &62u16.to_le_bytes()); // e_machine EM_X86_64
    put(&mut data, 0x28, &0x140u64.to_le_bytes()); // e_shoff
    put(&mut data, 0x34, &64u16.to_le_bytes()); // e_ehsize
    put(&mut data, 0x3a, &64u16.to_le_bytes()); // e_shentsize
    put(&mut data, 0x3c, &4u16.to_le_bytes()); // e_shnum
    put(&mut data, 0x3e, &3u16.to_le_bytes()); // e_shstrndx
    put(&mut data, 0x100, &[0x90; 16]);
    put(&mut data, 0x120, names);
    // sh_name, sh_type, sh_offset, sh_size per section.
    let sections = [
        (1u32, SHT_PROGBITS, 0x100u64, 16u64),
        (7, SHT_NOBITS, 0x110, 0x1000),
        (12, SHT_STRTAB, 0x120, names.len() as u64),
    ];
    for (index, (name, kind, offset, size)) in sections.into_iter().enumerate() {
        let header = 0x140 + (index + 1) * 64;
        put(&mut data, header, &name.to_le_bytes());
        put(&mut data, header + 4, &kind.to_le_bytes());
        put(&mut data, header + 24, &offset.to_le_bytes());
        put(&mut data, header + 32, &size.to_le_bytes());
    }
    data
}

/// PE32+ image: MZ header with `e_lfanew` 0x40, COFF header (AMD64, two
/// sections, 240 B optional header), 16 data directories, `.text` at 0x200
/// and `.rdata` at 0x400 (0x200 B each), and an attribute certificate table
/// at 0x600 holding one `WIN_CERTIFICATE` with the leaf certificate.
fn pe_with_certificate() -> Vec<u8> {
    let entry_len = 8 + LEAF.len();
    let table_len = entry_len.next_multiple_of(8);
    let mut data = vec![0u8; 0x600 + table_len];
    put(&mut data, 0, b"MZ");
    put(&mut data, 0x3c, &0x40u32.to_le_bytes());
    put(&mut data, 0x40, b"PE\0\0");
    let coff = 0x44;
    put(&mut data, coff, &IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
    put(&mut data, coff + 2, &2u16.to_le_bytes()); // NumberOfSections
    put(&mut data, coff + 16, &240u16.to_le_bytes()); // SizeOfOptionalHeader
    let optional = coff + 20;
    put(&mut data, optional, &PE32PLUS_MAGIC.to_le_bytes());
    put(&mut data, optional + 108, &16u32.to_le_bytes()); // NumberOfRvaAndSizes
    let security = optional + 112 + 4 * 8;
    put(&mut data, security, &0x600u32.to_le_bytes());
    put(&mut data, security + 4, &(table_len as u32).to_le_bytes());
    let table = optional + 240;
    for (index, (name, raw)) in [(b".text\0\0\0", 0x200u32), (b".rdata\0\0", 0x400)]
        .into_iter()
        .enumerate()
    {
        let header = table + index * 40;
        put(&mut data, header, name);
        put(&mut data, header + 16, &0x200u32.to_le_bytes()); // SizeOfRawData
        put(&mut data, header + 20, &raw.to_le_bytes()); // PointerToRawData
    }
    put(&mut data, 0x600, &(entry_len as u32).to_le_bytes());
    put(&mut data, 0x604, &WIN_CERT_REVISION_2_0.to_le_bytes());
    put(
        &mut data,
        0x606,
        &WIN_CERT_TYPE_PKCS_SIGNED_DATA.to_le_bytes(),
    );
    put(&mut data, 0x608, LEAF);
    data
}

/// DER element with a one-octet identifier and a minimal length.
fn der(identifier: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![identifier];
    match contents.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(contents);
    out
}

/// The children of the outer `SEQUENCE` of `data`, whose own identifiers
/// are single octets.
fn children(data: &[u8]) -> Vec<&[u8]> {
    let header = |at: usize| -> (usize, usize) {
        let first = data[at + 1];
        if first & 0x80 == 0 {
            return (2, usize::from(first));
        }
        let count = usize::from(first & 0x7f);
        let len = data[at + 2..at + 2 + count]
            .iter()
            .fold(0, |n, b| (n << 8) | usize::from(*b));
        (2 + count, len)
    };
    let (outer, _) = header(0);
    let mut at = outer;
    let mut items = Vec::new();
    while at < data.len() {
        let (h, len) = header(at);
        items.push(&data[at..at + h + len]);
        at += h + len;
    }
    items
}

/// `synthetic.im4m` with its placeholder chain replaced by the fixture
/// root and intermediate certificates.
fn im4m_with_certificates() -> Vec<u8> {
    let parts = children(IM4M);
    let mut contents: Vec<u8> = parts[..4].concat();
    contents.extend(der(0x30, &[ROOT, INTERMEDIATE].concat()));
    der(0x30, &contents)
}

#[test]
fn elf_sections_are_named_from_the_string_table_and_nobits_is_skipped() {
    let data = elf64();
    let found = regions(&data).unwrap();
    assert_eq!(labels(&found), vec![".text", ".shstrtab"]);
    let text = find(&found, ".text");
    assert_eq!(
        (text.kind, text.offset, text.size),
        (RegionKind::Section, 0x100, 16)
    );
}

#[test]
fn elf_section_counts_are_bounded_by_the_input() {
    let mut data = elf64();
    data[0x3c..0x3e].copy_from_slice(&0xffffu16.to_le_bytes());
    let found = regions(&data).unwrap();
    assert!(found.len() <= 4);
    // A table past the end yields no sections.
    let mut data = elf64();
    data[0x28..0x30].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(regions(&data).unwrap().is_empty());
}

#[test]
fn pe_sections_and_attribute_certificates_enclose_the_leaf() {
    let data = pe_with_certificate();
    let found = regions(&data).unwrap();
    assert_eq!(
        labels(&found),
        vec![
            ".text",
            ".rdata",
            "attribute certificate table",
            "WIN_CERTIFICATE (PKCS #7 SignedData)",
        ]
    );
    let entry = find(&found, "WIN_CERTIFICATE (PKCS #7 SignedData)");
    assert_eq!((entry.kind, entry.offset), (RegionKind::Signature, 0x600));
    let report = certificates::scan(&data);
    assert_eq!(report.certificates.len(), 1);
    let leaf = &report.certificates[0];
    let path: Vec<&str> = enclosing(&found, leaf.offset, leaf.stored_size)
        .iter()
        .map(|r| r.label.as_str())
        .collect();
    assert_eq!(
        path,
        vec![
            "attribute certificate table",
            "WIN_CERTIFICATE (PKCS #7 SignedData)"
        ]
    );
}

#[test]
fn a_table_filled_by_one_entry_still_encloses_it() {
    let mut data = pe_with_certificate();
    // Shrink the table to the entry's exact length, so both ranges are equal.
    let entry_len = (8 + LEAF.len()) as u32;
    let security = 0x44 + 20 + 112 + 4 * 8;
    data[security + 4..security + 8].copy_from_slice(&entry_len.to_le_bytes());
    let found = regions(&data).unwrap();
    let leaf = &certificates::scan(&data).certificates[0];
    let path: Vec<&str> = enclosing(&found, leaf.offset, leaf.stored_size)
        .iter()
        .map(|r| r.label.as_str())
        .collect();
    assert_eq!(
        path,
        vec![
            "attribute certificate table",
            "WIN_CERTIFICATE (PKCS #7 SignedData)"
        ]
    );
}

#[test]
fn pe_certificate_walk_stops_at_a_short_or_overlong_entry() {
    let mut data = pe_with_certificate();
    data[0x600..0x604].copy_from_slice(&4u32.to_le_bytes());
    assert!(!labels(&regions(&data).unwrap())
        .iter()
        .any(|l| l.starts_with("WIN_CERTIFICATE")));
    data[0x600..0x604].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(!labels(&regions(&data).unwrap())
        .iter()
        .any(|l| l.starts_with("WIN_CERTIFICATE")));
}

#[test]
fn macho_regions_cover_segments_sections_and_the_code_signature() {
    let data = gunzip("hello-arm64.gz");
    let found = regions(&data).unwrap();
    let image = zrax::formats::macho::parse_image(&data).unwrap();
    let signature = image.code_signature.unwrap();
    let region = find(&found, "Mach-O code signature");
    assert_eq!(
        (region.kind, region.offset, region.size),
        (
            RegionKind::Signature,
            u64::from(signature.offset),
            u64::from(signature.size)
        )
    );
    let text = find(&found, "__TEXT,__text");
    let path: Vec<&str> = enclosing(&found, text.offset, 4)
        .iter()
        .map(|r| r.label.as_str())
        .collect();
    assert_eq!(path, vec!["__TEXT", "__TEXT,__text"]);
    assert_eq!(find(&found, "__LINKEDIT").kind, RegionKind::Segment);
}

#[test]
fn fat_slices_place_their_segments_at_slice_offsets() {
    let arm64 = gunzip("hello-arm64.gz");
    let x86_64 = gunzip("hello-x86_64.gz");
    let align = 1usize << 14;
    let first = align;
    let second = (first + arm64.len()).next_multiple_of(align);
    let mut data = vec![0u8; second + x86_64.len()];
    put(&mut data, 0, &FAT_MAGIC.to_be_bytes());
    put(&mut data, 4, &2u32.to_be_bytes());
    // fat_arch: cputype, cpusubtype, offset, size, align.
    for (index, (cpu, offset, image)) in [
        (CPU_TYPE_ARM64, first, &arm64),
        (CPU_TYPE_X86_64, second, &x86_64),
    ]
    .into_iter()
    .enumerate()
    {
        let entry = 8 + index * 20;
        put(&mut data, entry, &cpu.to_be_bytes());
        put(&mut data, entry + 8, &(offset as u32).to_be_bytes());
        put(&mut data, entry + 12, &(image.len() as u32).to_be_bytes());
        put(&mut data, entry + 16, &14u32.to_be_bytes());
        put(&mut data, offset, image);
    }
    let found = regions(&data).unwrap();
    let slices: Vec<&Region> = found
        .iter()
        .filter(|r| r.kind == RegionKind::Member)
        .collect();
    assert_eq!(slices.len(), 2);
    assert_eq!(slices[1].offset, second as u64);
    let thin = regions(&x86_64).unwrap();
    let text = find(&thin, "__TEXT,__text");
    let in_fat: Vec<&Region> = found
        .iter()
        .filter(|r| r.label == "__TEXT,__text")
        .collect();
    assert_eq!(in_fat[1].offset, second as u64 + text.offset);
    let path = enclosing(&found, in_fat[1].offset, 1);
    assert_eq!(path[0].kind, RegionKind::Member);
    assert_eq!(path.last().unwrap().label, "__TEXT,__text");
}

#[test]
fn im4m_chain_encloses_the_certificates_it_holds() {
    let data = im4m_with_certificates();
    let found = regions(&data).unwrap();
    assert_eq!(
        labels(&found),
        vec!["IM4M manifest", "IM4M signature", "IM4M certificate chain"]
    );
    assert_eq!(
        find(&found, "IM4M certificate chain").kind,
        RegionKind::Certificates
    );
    let report = certificates::scan(&data);
    assert_eq!(report.certificates.len(), 2);
    for certificate in &report.certificates {
        let path = enclosing(&found, certificate.offset, certificate.stored_size);
        assert_eq!(path.last().unwrap().label, "IM4M certificate chain");
    }
}

#[test]
fn img4_lists_its_manifest_and_payload_member() {
    let found = regions(IMG4).unwrap();
    let names = labels(&found);
    assert!(names.contains(&"IM4M manifest"), "{names:?}");
    assert!(names.contains(&"IM4M certificate chain"), "{names:?}");
    assert!(found.iter().any(|r| r.kind == RegionKind::Member));
}

#[test]
fn archive_members_are_regions_at_their_stored_ranges() {
    let found = regions(TAR).unwrap();
    assert!(!found.is_empty());
    assert!(found.iter().all(|r| r.kind == RegionKind::Member));
    let subfiles = zrax::inspection::subfiles(TAR).unwrap();
    for subfile in &subfiles {
        assert!(found
            .iter()
            .any(|r| r.label == subfile.label && r.offset == subfile.offset as u64));
    }
}

#[test]
fn inputs_without_structure_have_no_regions() {
    assert!(regions(b"plain bytes").unwrap().is_empty());
    assert!(regions(&[]).unwrap().is_empty());
}

#[test]
fn truncations_and_mutations_do_not_panic() {
    for data in [elf64(), pe_with_certificate(), im4m_with_certificates()] {
        for end in 0..data.len() {
            let _ = regions(&data[..end]);
        }
        for at in 0..data.len().min(0x400) {
            for value in [0x00, 0xff, data[at] ^ 0x80] {
                let mut mutated = data.clone();
                mutated[at] = value;
                if let Ok(found) = regions(&mutated) {
                    assert!(found
                        .iter()
                        .all(|r| r.offset + r.size <= mutated.len() as u64));
                }
            }
        }
    }
}
