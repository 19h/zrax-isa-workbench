//! Microsoft cabinets: synthetic cabinets built from the documented layout
//! (the Cabinet SDK's "Microsoft Cabinet Format", [MS-MCI], [MS-PATCH],
//! libmspack `cabd.c`) with stored, MSZIP and LZX folders, cabinet sets,
//! reserve areas and a signature reserve; corrupted structures and
//! checksums, limits, and truncation and mutation sweeps; and real
//! cabinets from the directory `CAB_SAMPLES_DIR` names, when it is set.

#[path = "support/lzx.rs"]
mod lzx;

use lzx::{Block, Token};
use zrax::formats::cab::{self, Layout};
use zrax::formats::compressed::{self, Codec};
use zrax::formats::container::{self, Child, Classify, Container, Kind, MAX_COMPONENTS};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

/// `flags` bits (SDK "CFHEADER").
const PREV_CABINET: u16 = 0x0001;
const NEXT_CABINET: u16 = 0x0002;
const RESERVE_PRESENT: u16 = 0x0004;

/// `typeCompress` values (Wine `fdi.h`); LZX keeps its window in bits 8-12.
const TYPE_NONE: u16 = 0;
const TYPE_MSZIP: u16 = 1;
const TYPE_QUANTUM: u16 = 2;
const TYPE_LZX: u16 = 3;

/// `iFolder` values of files that span cabinets (SDK "CFFILE").
const CONTINUED_FROM_PREV: u16 = 0xFFFD;
const CONTINUED_TO_NEXT: u16 = 0xFFFE;
const CONTINUED_PREV_AND_NEXT: u16 = 0xFFFF;

/// `attribs` bits (SDK "CFFILE").
const A_ARCH: u16 = 0x20;
const A_EXEC: u16 = 0x40;
const A_NAME_IS_UTF: u16 = 0x80;

/// Uncompressed bytes of a full CFDATA block.
const BLOCK: usize = 32 << 10;

/// The fixed CFHEADER fields, and the fixed parts of CFFOLDER, CFFILE and
/// CFDATA entries.
const CFHEADER_SIZE: usize = 36;
const CFFOLDER_SIZE: usize = 8;
const CFFILE_SIZE: usize = 16;
const CFDATA_SIZE: usize = 8;

/// The ELF machine for x86-64.
const EM_X86_64: u16 = 62;

/// `CSUMCompute` from the SDK's "Checksum Method": little-endian words
/// XORed into the seed, then the 1-3 remaining bytes, the first of them
/// most significant.
fn csum(bytes: &[u8], seed: u32) -> u32 {
    let mut sum = seed;
    let words = bytes.len() / 4;
    for i in 0..words {
        sum ^= u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap());
    }
    let rest = &bytes[4 * words..];
    let tail = match rest.len() {
        3 => u32::from(rest[0]) << 16 | u32::from(rest[1]) << 8 | u32::from(rest[2]),
        2 => u32::from(rest[0]) << 8 | u32::from(rest[1]),
        1 => u32::from(rest[0]),
        _ => 0,
    };
    sum ^ tail
}

/// How a block's `csum` is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sum {
    /// The SDK's checksum over the data and then `cbData`, `cbUncomp`.
    Computed,
    /// 0: not supplied.
    Absent,
    /// The computed checksum with its low bit flipped.
    Wrong,
}

/// One CFDATA block: its data bytes and `cbUncomp`.
#[derive(Debug, Clone)]
struct DataBlock {
    data: Vec<u8>,
    uncompressed: u16,
    sum: Sum,
}

/// One CFFOLDER entry and the folder's CFDATA blocks.
#[derive(Debug, Clone)]
struct FolderSpec {
    type_compress: u16,
    blocks: Vec<DataBlock>,
}

/// One CFFILE entry.
#[derive(Debug, Clone)]
struct FileSpec {
    name: Vec<u8>,
    /// `cbFile` and `uoffFolderStart`.
    size: u32,
    offset: u32,
    /// `iFolder`.
    folder: u16,
    attributes: u16,
}

/// The reserve sizes and the per-cabinet reserve bytes.
#[derive(Debug, Clone, Default)]
struct Reserve {
    header: Vec<u8>,
    folder: u8,
    data: u8,
}

/// A cabinet to build.
#[derive(Debug, Clone)]
struct Cabinet {
    /// `versionMinor`, `versionMajor`.
    version: [u8; 2],
    /// Flag bits to set besides the ones the fields below imply.
    extra_flags: u16,
    set_id: u16,
    index: u16,
    reserve: Option<Reserve>,
    /// Cabinet and disk names of the neighbors.
    previous: Option<(String, String)>,
    next: Option<(String, String)>,
    folders: Vec<FolderSpec>,
    files: Vec<FileSpec>,
    /// Bytes added between the CFFOLDER and CFFILE tables.
    table_gap: usize,
}

/// A built cabinet and where its parts are.
struct Built {
    bytes: Vec<u8>,
    /// `coffFiles`.
    files_offset: usize,
    /// For each folder, the file offset of each CFDATA header.
    blocks: Vec<Vec<usize>>,
    /// Bytes of each CFDATA header including its reserve.
    data_header: usize,
}

impl Built {
    /// File offset of the data bytes of block `b` of folder `f`.
    fn data_at(&self, f: usize, b: usize) -> usize {
        self.blocks[f][b] + self.data_header
    }
}

impl Cabinet {
    fn new(folders: Vec<FolderSpec>, files: Vec<FileSpec>) -> Self {
        Self {
            version: [3, 1],
            extra_flags: 0,
            set_id: 0x1234,
            index: 0,
            reserve: None,
            previous: None,
            next: None,
            folders,
            files,
            table_gap: 0,
        }
    }

    /// CFHEADER (`MSCF`, `reserved1`, `cbCabinet`, `reserved2`,
    /// `coffFiles`, `reserved3`, `versionMinor`, `versionMajor`,
    /// `cFolders`, `cFiles`, `flags`, `setID`, `iCabinet`), then the reserve
    /// sizes (`cbCFHeader` u16, `cbCFFolder`, `cbCFData`) and area, the
    /// neighbor names (cabinet and disk, NUL-terminated), the CFFOLDER
    /// entries (`coffCabStart`, `cCFData`, `typeCompress`, reserve), the
    /// CFFILE entries (`cbFile`, `uoffFolderStart`, `iFolder`, `date`,
    /// `time`, `attribs`, `szName` and NUL), then each folder's CFDATA
    /// blocks (`csum`, `cbData`, `cbUncomp`, reserve, data).
    fn build(&self) -> Built {
        let reserve = self.reserve.clone().unwrap_or_default();
        let mut flags = self.extra_flags;
        if self.reserve.is_some() {
            flags |= RESERVE_PRESENT;
        }
        if self.previous.is_some() {
            flags |= PREV_CABINET;
        }
        if self.next.is_some() {
            flags |= NEXT_CABINET;
        }
        let mut optional = Vec::new();
        if self.reserve.is_some() {
            optional.extend_from_slice(&(reserve.header.len() as u16).to_le_bytes());
            optional.push(reserve.folder);
            optional.push(reserve.data);
            optional.extend_from_slice(&reserve.header);
        }
        for (cabinet, disk) in self.previous.iter().chain(&self.next) {
            optional.extend_from_slice(cabinet.as_bytes());
            optional.push(0);
            optional.extend_from_slice(disk.as_bytes());
            optional.push(0);
        }
        let folder_entry = CFFOLDER_SIZE + usize::from(reserve.folder);
        let folders_offset = CFHEADER_SIZE + optional.len();
        let files_offset = folders_offset + self.folders.len() * folder_entry + self.table_gap;
        let mut file_table = Vec::new();
        for file in &self.files {
            file_table.extend_from_slice(&file.size.to_le_bytes());
            file_table.extend_from_slice(&file.offset.to_le_bytes());
            file_table.extend_from_slice(&file.folder.to_le_bytes());
            file_table.extend_from_slice(&0x226Cu16.to_le_bytes());
            file_table.extend_from_slice(&0x59BAu16.to_le_bytes());
            file_table.extend_from_slice(&file.attributes.to_le_bytes());
            file_table.extend_from_slice(&file.name);
            file_table.push(0);
        }
        let data_header = CFDATA_SIZE + usize::from(reserve.data);
        let mut data = Vec::new();
        let mut folder_table = Vec::new();
        let mut blocks = Vec::new();
        let data_start = files_offset + file_table.len();
        for folder in &self.folders {
            let start = data_start + data.len();
            folder_table.extend_from_slice(&(start as u32).to_le_bytes());
            folder_table.extend_from_slice(&(folder.blocks.len() as u16).to_le_bytes());
            folder_table.extend_from_slice(&folder.type_compress.to_le_bytes());
            folder_table.extend(std::iter::repeat(0xA5).take(usize::from(reserve.folder)));
            let mut offsets = Vec::new();
            for block in &folder.blocks {
                offsets.push(data_start + data.len());
                let mut sizes = (block.data.len() as u16).to_le_bytes().to_vec();
                sizes.extend_from_slice(&block.uncompressed.to_le_bytes());
                let computed = csum(&sizes, csum(&block.data, 0));
                let sum = match block.sum {
                    Sum::Computed => computed,
                    Sum::Absent => 0,
                    Sum::Wrong => computed ^ 1,
                };
                data.extend_from_slice(&sum.to_le_bytes());
                data.extend_from_slice(&sizes);
                data.extend(std::iter::repeat(0x5A).take(usize::from(reserve.data)));
                data.extend_from_slice(&block.data);
            }
            blocks.push(offsets);
        }
        let total = data_start + data.len();
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(b"MSCF");
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(total as u32).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(files_offset as u32).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&self.version);
        bytes.extend_from_slice(&(self.folders.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(self.files.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&flags.to_le_bytes());
        bytes.extend_from_slice(&self.set_id.to_le_bytes());
        bytes.extend_from_slice(&self.index.to_le_bytes());
        bytes.extend_from_slice(&optional);
        bytes.extend_from_slice(&folder_table);
        bytes.extend(std::iter::repeat(0).take(self.table_gap));
        bytes.extend_from_slice(&file_table);
        bytes.extend_from_slice(&data);
        assert_eq!(bytes.len(), total);
        Built {
            bytes,
            files_offset,
            blocks,
            data_header,
        }
    }
}

/// An x86-64 ELF header (magic, class 2, little-endian, version 1, type 2,
/// machine 62) followed by `fill` up to `size` bytes.
fn elf(size: usize, fill: u8) -> Vec<u8> {
    let mut data = vec![fill; size.max(64)];
    data[..64].fill(0);
    data[..4].copy_from_slice(b"\x7fELF");
    data[4] = 2;
    data[5] = 1;
    data[6] = 1;
    data[16..18].copy_from_slice(&2u16.to_le_bytes());
    data[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
    data
}

/// The minimal x86-64 PE32+ image of the UEFI fixtures (after the 4-byte
/// section header of `pe32-sections.bin`, 0x1AC bytes).
fn pe() -> Vec<u8> {
    let sections = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/uefi/pe32-sections.bin"
    ))
    .expect("fixture is committed");
    sections[4..0x1B0].to_vec()
}

const README: &[u8] = b"Release notes: nothing to see here.\r\n";

/// The files of one folder, back to back from offset 0, and the folder's
/// uncompressed bytes.
fn pack(folder: u16, members: &[(&str, &[u8])]) -> (Vec<FileSpec>, Vec<u8>) {
    let mut files = Vec::new();
    let mut bytes = Vec::new();
    for &(name, data) in members {
        files.push(FileSpec {
            name: name.as_bytes().to_vec(),
            size: data.len() as u32,
            offset: bytes.len() as u32,
            folder,
            attributes: A_ARCH,
        });
        bytes.extend_from_slice(data);
    }
    (files, bytes)
}

/// A stored folder: blocks of at most 32 KiB.
fn stored(data: &[u8]) -> FolderSpec {
    FolderSpec {
        type_compress: TYPE_NONE,
        blocks: data
            .chunks(BLOCK)
            .map(|chunk| DataBlock {
                data: chunk.to_vec(),
                uncompressed: chunk.len() as u16,
                sum: Sum::Computed,
            })
            .collect(),
    }
}

/// An MSZIP folder: each 32 KiB block is `CK` and that block compressed
/// on its own as raw DEFLATE.
fn mszip(data: &[u8]) -> FolderSpec {
    FolderSpec {
        type_compress: TYPE_MSZIP,
        blocks: data
            .chunks(BLOCK)
            .map(|chunk| {
                let mut block = b"CK".to_vec();
                block.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(chunk, 6));
                DataBlock {
                    data: block,
                    uncompressed: chunk.len() as u16,
                    sum: Sum::Computed,
                }
            })
            .collect(),
    }
}

/// An LZX folder with a 2^`window_bits` window: one CFDATA block per frame
/// of `stream`.
fn lzx_folder(window_bits: u8, stream: &lzx::Stream) -> FolderSpec {
    let frames = stream.frames();
    let blocks = frames
        .iter()
        .enumerate()
        .map(|(i, frame)| DataBlock {
            data: frame.clone(),
            uncompressed: (stream.window.len() - i * BLOCK).min(BLOCK) as u16,
            sum: Sum::Computed,
        })
        .collect();
    FolderSpec {
        type_compress: TYPE_LZX | u16::from(window_bits) << 8,
        blocks,
    }
}

/// Writes DEFLATE bits, least significant first (RFC 1951, 3.1.1).
#[derive(Default)]
struct DeflateBits {
    bytes: Vec<u8>,
    bit: usize,
}

impl DeflateBits {
    fn put(&mut self, value: u32, count: u32) {
        for i in 0..count {
            if self.bit % 8 == 0 {
                self.bytes.push(0);
            }
            if (value >> i) & 1 == 1 {
                *self.bytes.last_mut().unwrap() |= 1 << (self.bit % 8);
            }
            self.bit += 1;
        }
    }

    /// A Huffman code, most significant bit first.
    fn code(&mut self, code: u32, length: u32) {
        for i in (0..length).rev() {
            self.put((code >> i) & 1, 1);
        }
    }
}

/// An MSZIP block of one final fixed-Huffman DEFLATE block (RFC 1951,
/// 3.2.6) that copies 258 bytes (length code 285) from 0x7F00 bytes back
/// (distance code 29: base 24577, 13 extra bits), then ends (code 256).
fn mszip_history_block() -> Vec<u8> {
    let mut w = DeflateBits::default();
    w.put(1, 1);
    w.put(1, 2);
    w.code(0xC0 + (285 - 280), 8);
    w.code(29, 5);
    w.put(0x7F00 - 24577, 13);
    w.code(0, 7);
    let mut block = b"CK".to_vec();
    block.extend_from_slice(&w.bytes);
    block
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn parse(data: &[u8]) -> Container<'_> {
    container::parse(data, Kind::Cab(Layout::Cabinet)).expect("parses")
}

fn parse_error(data: &[u8]) -> String {
    cab::parse_container(data, Layout::Cabinet)
        .expect_err("is a parse error")
        .to_string()
}

fn labels(c: &Container<'_>) -> Vec<String> {
    c.children.iter().map(|child| child.label.clone()).collect()
}

fn child<'c>(c: &'c Container<'_>, label: &str) -> &'c Child<'c> {
    c.children
        .iter()
        .find(|child| child.label == label)
        .unwrap_or_else(|| panic!("child {label} in {:?}", labels(c)))
}

fn assert_note(c: &Container<'_>, text: &str) {
    assert!(
        c.notes.iter().any(|n| n.contains(text)),
        "no note {text:?} in {:#?}",
        c.notes
    );
}

fn metadata<'p>(p: &'p DetectionPayload, key: &str) -> &'p zrax::MetadataValue {
    &p.metadata
        .iter()
        .find(|m| matches!(&m.key, zrax::MetadataKey::Custom(k) if k == key))
        .unwrap_or_else(|| panic!("metadata {key}"))
        .value
}

/// The SDK's sample (two stored text files) plus an ELF and a PE file.
fn stored_cabinet() -> Cabinet {
    let elf = elf(200, 0x90);
    let pe = pe();
    let (files, data) = pack(
        0,
        &[
            ("readme.txt", README),
            ("bin\\tool", &elf),
            ("bin\\driver.sys", &pe),
        ],
    );
    Cabinet::new(vec![stored(&data)], files)
}

#[test]
fn stored_cabinets_list_recognized_files_by_name_at_their_stored_offsets() {
    let cabinet = stored_cabinet();
    let built = cabinet.build();
    assert_eq!(cab::detect(&built.bytes), Some(Layout::Cabinet));
    let c = parse(&built.bytes);
    assert_eq!(c.format, FileFormat::MsCab);
    assert_eq!(c.variant, "MSCF cabinet");
    assert_eq!(c.target, None, "a cabinet names no CPU");
    assert_eq!(c.consumed, built.bytes.len());
    assert_eq!(labels(&c), ["bin\\tool", "bin\\driver.sys"]);
    let data = built.data_at(0, 0);
    let tool = child(&c, "bin\\tool");
    assert_eq!(tool.offset, data + README.len());
    assert_eq!(tool.stored_size, 200);
    assert_eq!(tool.transform, None);
    assert_eq!(tool.classify, Classify::IfRecognized);
    assert_eq!(&built.bytes[tool.offset..tool.offset + 4], b"\x7fELF");
    let driver = child(&c, "bin\\driver.sys");
    assert_eq!(driver.offset, data + README.len() + 200);
    assert_eq!(&*driver.data, &pe()[..]);
    assert_note(&c, "Cabinet format 1.3; 1 folder: stored; 3 files");
    assert_note(&c, "CFDATA checksums verified for 1 of 1 blocks");
    assert_note(
        &c,
        "2 of 3 examined files are in a recognized format and listed",
    );

    let p = classify(&built.bytes);
    assert_eq!(p.format.format, FileFormat::MsCab);
    assert_eq!(p.format.variant_name.as_deref(), Some("MSCF cabinet"));
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_eq!(p.slices.len(), 2);
    assert_eq!(p.slices[0].label.as_deref(), Some("bin\\tool"));
    assert_eq!(p.slices[0].offset, (data + README.len()) as u64);
    assert_eq!(
        p.slices[1].isa,
        Isa::X86_64,
        "the PE driver is classified by the PE parser"
    );
    assert_eq!(metadata(&p, "cab_files").to_string(), "3");
    assert_eq!(metadata(&p, "cab_set_id").to_string(), "0x1234");
    assert!(metadata(&p, "cab_folder_0")
        .to_string()
        .starts_with("stored; typeCompress 0x0000; 1 CFDATA block at 0x"));
}

#[test]
fn stored_files_that_span_blocks_are_reassembled() {
    let big = elf(70_000, 0xC3);
    let (files, data) = pack(0, &[("readme.txt", README), ("big.elf", &big)]);
    let cabinet = Cabinet::new(vec![stored(&data)], files);
    let built = cabinet.build();
    let c = parse(&built.bytes);
    let member = child(&c, "big.elf");
    assert_eq!(member.transform, Some("CFDATA blocks"));
    assert_eq!(&*member.data, &big[..]);
    let first = built.data_at(0, 0) + README.len();
    assert_eq!(member.offset, first);
    // From the first byte to the last, two CFDATA headers between.
    let last = built.data_at(0, 2) + (README.len() + big.len() - 2 * BLOCK);
    assert_eq!(member.stored_size, last - first);
    assert_note(&c, "CFDATA checksums verified for 3 of 3 blocks");
}

/// An MSZIP cabinet whose second block copies 258 bytes of the first from
/// 0x7F00 bytes back, so it decodes only with the first block's history:
/// `one.elf` is block 1 (an ELF header, a pattern, and a second ELF header
/// at 0x100); `tail.elf` is the 258 copied bytes, which start with that
/// header. Returns the cabinet and the folder's uncompressed bytes.
fn mszip_history_cabinet() -> (Cabinet, Vec<u8>) {
    let copy_from = BLOCK - 0x7F00;
    let mut first = elf(BLOCK, 0);
    for (i, b) in first.iter_mut().enumerate().skip(64) {
        *b = (i % 251) as u8;
    }
    first[copy_from..copy_from + 64].copy_from_slice(&elf(64, 0));
    let mut expected = first.clone();
    expected.extend_from_slice(&first[copy_from..copy_from + 258]);
    let mut folder = mszip(&first);
    folder.blocks.push(DataBlock {
        data: mszip_history_block(),
        uncompressed: 258,
        sum: Sum::Computed,
    });
    let files = vec![
        FileSpec {
            name: b"one.elf".to_vec(),
            size: BLOCK as u32,
            offset: 0,
            folder: 0,
            attributes: A_ARCH,
        },
        FileSpec {
            name: b"tail.elf".to_vec(),
            size: 258,
            offset: BLOCK as u32,
            folder: 0,
            attributes: A_ARCH,
        },
    ];
    (Cabinet::new(vec![folder], files), expected)
}

#[test]
fn mszip_folders_decode_with_the_history_of_earlier_blocks() {
    let (cabinet, expected) = mszip_history_cabinet();
    let built = cabinet.build();
    let c = parse(&built.bytes);
    assert_eq!(labels(&c), ["one.elf", "tail.elf"]);
    let one = child(&c, "one.elf");
    assert_eq!(one.transform, Some("MSZIP"));
    assert_eq!(&*one.data, &expected[..BLOCK]);
    assert_eq!(one.offset, built.data_at(0, 0));
    assert_eq!(
        one.stored_size,
        built.blocks[0][1] - built.data_at(0, 0),
        "the stored extent is the block's data"
    );
    let tail = child(&c, "tail.elf");
    assert_eq!(&*tail.data, &expected[BLOCK..]);
    assert_eq!(tail.offset, built.data_at(0, 1));
    assert_note(&c, "1 folder: MSZIP");
    // Without the history the second block does not decode.
    let block = mszip_history_block();
    assert!(compressed::inflate_continuing(&block[2..], &mut Vec::new(), 258).is_err());
}

#[test]
fn mszip_failures_leave_the_folder_out_with_a_note() {
    let (files, data) = pack(0, &[("a.elf", &elf(100, 1))]);
    let mut folder = mszip(&data);
    folder.blocks[0].data[0] = b'X';
    let built = Cabinet::new(vec![folder], files.clone()).build();
    let c = parse(&built.bytes);
    assert!(c.children.is_empty());
    assert_note(&c, "Folder 0 (MSZIP): the MSZIP block at 0x");
    assert_note(
        &c,
        "does not start with the signature CK; 1 file was not extracted",
    );

    let mut long = mszip(&data);
    long.blocks[0].uncompressed = 101;
    let built = Cabinet::new(vec![long], files.clone()).build();
    let c = parse(&built.bytes);
    assert!(c.children.is_empty());
    assert_note(&c, "decodes to 100 B; its cbUncomp is 101 B");
    let mut short = mszip(&data);
    short.blocks[0].uncompressed = 99;
    let mut short_files = files.clone();
    short_files[0].size = 99;
    let built = Cabinet::new(vec![short], short_files).build();
    let c = parse(&built.bytes);
    assert_note(&c, "does not decode: Decoded payload exceeds 99 B");

    let mut corrupt = mszip(&data);
    let last = corrupt.blocks[0].data.len() - 1;
    corrupt.blocks[0].data.truncate(last);
    let built = Cabinet::new(vec![corrupt], files).build();
    let c = parse(&built.bytes);
    assert_note(&c, "does not decode: Truncated DEFLATE stream");
}

/// An LZX stream of three frames that uses every block type and token
/// kind: an aligned offset block (offsets with 3+ footer bits), a verbatim
/// block with long matches (length tree) and repeated offsets, and an
/// odd-sized uncompressed block. Frame 0 starts with an ELF header.
fn lzx_stream(window_bits: u8, e8: Option<u32>) -> lzx::Stream {
    let header = elf(64, 0);
    let mut first = lzx::literals(&header);
    first.extend(lzx::literals(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"));
    // 1000 B of matches 36 back (5 footer bits), then repeats.
    for _ in 0..4 {
        first.push(Token::Match {
            length: 250,
            offset: 36,
        });
    }
    // Fill frame 0: 32768 - 64 - 36 - 1000 = 31668 B more.
    let mut left = BLOCK - 64 - 36 - 1000;
    while left > 0 {
        let length = left.min(257);
        if length < 2 {
            first.push(Token::Literal(b'!'));
            left -= 1;
            continue;
        }
        first.push(Token::Match {
            length,
            offset: 1000,
        });
        left -= length;
    }
    let text = b"frame one: plain literals, then a long match";
    let mut second = lzx::literals(text);
    second.push(Token::Match {
        length: 200,
        offset: 45,
    });
    // Repeated offsets R1 and R2 after two new offsets.
    second.push(Token::Match {
        length: 9,
        offset: 20_000,
    });
    second.push(Token::Match {
        length: 9,
        offset: 30_000,
    });
    second.push(Token::Match {
        length: 3,
        offset: 20_000,
    });
    second.push(Token::Match {
        length: 3,
        offset: 45,
    });
    let used = text.len() + 200 + 9 + 9 + 3 + 3;
    // An odd-sized uncompressed block that ends in frame 2, so a pad byte
    // precedes the last block.
    let mut tail = vec![b'u'; BLOCK - used];
    tail.extend_from_slice(b"third frame, stored!");
    lzx::encode(
        window_bits,
        e8,
        &[
            Block::Aligned(first),
            Block::Verbatim(second),
            Block::Uncompressed(tail),
            Block::Verbatim(lzx::literals(b"end")),
        ],
    )
}

#[test]
fn lzx_folders_decode_every_block_type_across_frames() {
    let stream = lzx_stream(16, None);
    assert_eq!(stream.frame_ends.len(), 3);
    let total = stream.window.len();
    assert_eq!(total, 2 * BLOCK + 23);
    let decoded =
        compressed::decode_limited(Codec::Lzx { window_bits: 16 }, &stream.bytes, total).unwrap();
    assert_eq!(decoded.data, stream.window);
    assert_eq!(decoded.consumed, Some(stream.bytes.len()));
    // Every frame is its own CFDATA block.
    let folder = lzx_folder(16, &stream);
    let files = vec![
        FileSpec {
            name: b"program.elf".to_vec(),
            size: BLOCK as u32,
            offset: 0,
            folder: 0,
            attributes: A_ARCH,
        },
        FileSpec {
            name: b"rest.txt".to_vec(),
            size: (total - BLOCK) as u32,
            offset: BLOCK as u32,
            folder: 0,
            attributes: A_ARCH,
        },
    ];
    let built = Cabinet::new(vec![folder], files).build();
    let c = parse(&built.bytes);
    assert_eq!(labels(&c), ["program.elf"]);
    let program = child(&c, "program.elf");
    assert_eq!(program.transform, Some("LZX"));
    assert_eq!(&*program.data, &stream.window[..BLOCK]);
    assert_eq!(program.offset, built.data_at(0, 0));
    assert_note(&c, "1 folder: LZX (2^16 B window)");
    let p = classify(&built.bytes);
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_eq!(p.slices[0].decoded.as_ref().unwrap().transform, "LZX");
}

#[test]
fn lzx_e8_translation_is_undone_per_frame() {
    // A CALL at output 0x100 whose stored operand is the absolute target
    // 0x1234: decoded, it is 0x1234 - 0x100 relative. One at the frame's
    // last 10 bytes stays as stored.
    let mut bytes = elf(BLOCK, 0x90);
    bytes[0x100] = 0xE8;
    bytes[0x101..0x105].copy_from_slice(&0x1234u32.to_le_bytes());
    bytes[BLOCK - 8] = 0xE8;
    bytes[BLOCK - 7..BLOCK - 3].copy_from_slice(&0x1234u32.to_le_bytes());
    let stream = lzx::encode(15, Some(0x0100_0000), &[Block::Uncompressed(bytes.clone())]);
    let mut expected = bytes;
    expected[0x101..0x105].copy_from_slice(&(0x1234u32 - 0x100).to_le_bytes());
    let decoded =
        compressed::decode_limited(Codec::Lzx { window_bits: 15 }, &stream.bytes, BLOCK).unwrap();
    assert_eq!(decoded.data, expected);
}

#[test]
fn lzx_folders_whose_inner_blocks_are_short_are_not_decoded() {
    let stream = lzx_stream(16, None);
    let mut folder = lzx_folder(16, &stream);
    folder.blocks[0].uncompressed = (BLOCK - 2) as u16;
    let files = vec![FileSpec {
        name: b"program.elf".to_vec(),
        size: 100,
        offset: 0,
        folder: 0,
        attributes: A_ARCH,
    }];
    let built = Cabinet::new(vec![folder], files.clone()).build();
    let c = parse(&built.bytes);
    assert!(c.children.is_empty());
    assert_note(
        &c,
        "decodes to 32766 B; only a folder's last block may be shorter than 32 KiB",
    );

    let mut bad_window = lzx_folder(16, &stream);
    bad_window.type_compress = TYPE_LZX | 22 << 8;
    let built = Cabinet::new(vec![bad_window], files.clone()).build();
    let c = parse(&built.bytes);
    assert_note(&c, "Unsupported LZX window of 2^22 B");

    // The high byte of the first word holds the E8 bit and the block type.
    let mut corrupt = lzx_folder(16, &stream);
    corrupt.blocks[0].data[1] = 0;
    let built = Cabinet::new(vec![corrupt], files).build();
    let c = parse(&built.bytes);
    assert!(c.children.is_empty());
    assert_note(
        &c,
        "Folder 0 (LZX (2^16 B window)): the LZX stream does not decode: Invalid LZX block type 0",
    );
}

#[test]
fn quantum_and_undefined_folders_are_left_out_with_a_note() {
    let (files, data) = pack(0, &[("a.elf", &elf(100, 1))]);
    let mut quantum = stored(&data);
    quantum.type_compress = TYPE_QUANTUM | 4 << 4 | 18 << 8;
    let built = Cabinet::new(vec![quantum], files.clone()).build();
    let c = parse(&built.bytes);
    assert!(c.children.is_empty());
    assert_note(&c, "1 folder: Quantum (level 4, 2^18 B window)");
    assert_note(
        &c,
        "Folder 0 (Quantum (level 4, 2^18 B window)): Quantum compression is not decoded; 1 file \
         was not extracted",
    );
    let mut unknown = stored(&data);
    unknown.type_compress = 7;
    let built = Cabinet::new(vec![unknown], files).build();
    let c = parse(&built.bytes);
    assert_note(&c, "compression type 7 is not defined");
}

#[test]
fn checksum_mismatches_leave_the_folder_out_and_zero_checksums_are_unchecked() {
    let (files_a, data_a) = pack(0, &[("a.elf", &elf(100, 1))]);
    let (mut files_b, data_b) = pack(1, &[("b.elf", &elf(100, 2))]);
    files_b[0].folder = 1;
    let mut good = stored(&data_a);
    good.blocks[0].sum = Sum::Absent;
    let mut bad = stored(&data_b);
    bad.blocks[0].sum = Sum::Wrong;
    let files = [files_a, files_b].concat();
    let built = Cabinet::new(vec![good, bad], files).build();
    let c = parse(&built.bytes);
    assert_eq!(labels(&c), ["a.elf"]);
    assert_note(
        &c,
        "CFDATA checksums verified for 0 of 2 blocks; 1 block carries no checksum (csum 0); 1 \
         does not match",
    );
    assert_note(&c, "Folder 1 (stored): CFDATA checksum 0x");
    assert_note(
        &c,
        &format!("at 0x{:X} does not match the computed", built.blocks[1][0]),
    );
}

#[test]
fn cabinet_sets_name_continued_files_and_skip_split_blocks() {
    // Cabinet 1 of a set: folder 0 began in the previous cabinet; folder 1
    // is whole; folder 2 continues in the next cabinet with a split block.
    let continued = stored(&[0x11; 100]);
    let (mut whole_files, whole) = pack(1, &[("whole.elf", &elf(300, 3))]);
    whole_files[0].folder = 1;
    let mut last = stored(&[elf(120, 4), vec![0x22; 50]].concat());
    last.blocks.push(DataBlock {
        data: vec![0x33; 40],
        uncompressed: 0,
        sum: Sum::Computed,
    });
    let mut files = vec![FileSpec {
        name: b"begins-before.bin".to_vec(),
        size: 5000,
        offset: 0,
        folder: CONTINUED_FROM_PREV,
        attributes: A_ARCH,
    }];
    files.push(FileSpec {
        name: b"old-folder.elf".to_vec(),
        size: 50,
        offset: 4950,
        folder: 0,
        attributes: A_ARCH,
    });
    files.extend(whole_files);
    files.push(FileSpec {
        name: b"tail-start.elf".to_vec(),
        size: 120,
        offset: 0,
        folder: 2,
        attributes: A_ARCH,
    });
    files.push(FileSpec {
        name: b"spans.bin".to_vec(),
        size: 9000,
        offset: 120,
        folder: CONTINUED_TO_NEXT,
        attributes: A_ARCH,
    });
    let mut cabinet = Cabinet::new(vec![continued, stored(&whole), last], files);
    cabinet.index = 1;
    cabinet.previous = Some(("set1.cab".into(), "Disk 1".into()));
    cabinet.next = Some(("set3.cab".into(), String::new()));
    let built = cabinet.build();
    let c = parse(&built.bytes);
    assert_eq!(labels(&c), ["whole.elf", "tail-start.elf"]);
    assert_note(
        &c,
        "Cabinet 1 of set 0x1234; previous cabinet `set1.cab` (disk `Disk 1`); next cabinet \
         `set3.cab`",
    );
    assert_note(
        &c,
        "Files that begin in the previous cabinet `set1.cab` are not joined: `begins-before.bin`",
    );
    assert_note(
        &c,
        "Files that continue in the next cabinet `set3.cab` are not joined: `spans.bin`",
    );
    assert_note(
        &c,
        "Folder 0 began in the previous cabinet, so its files were not extracted: `old-folder.elf`",
    );
    let p = classify(&built.bytes);
    assert!(metadata(&p, "cab_folder_2")
        .to_string()
        .ends_with("last block continues in the next cabinet"));
    assert_eq!(metadata(&p, "cab_previous_cabinet").to_string(), "set1.cab");

    // Both directions at once, in a one-folder cabinet.
    let mut middle = Cabinet::new(
        vec![stored(&[0x44; 10])],
        vec![FileSpec {
            name: b"middle.bin".to_vec(),
            size: 100_000,
            offset: 0,
            folder: CONTINUED_PREV_AND_NEXT,
            attributes: A_ARCH,
        }],
    );
    middle.previous = Some(("a.cab".into(), String::new()));
    middle.next = Some(("c.cab".into(), String::new()));
    let built = middle.build();
    let c = parse(&built.bytes);
    assert_note(
        &c,
        "begin in the previous cabinet `a.cab` are not joined: `middle.bin`",
    );
    assert_note(
        &c,
        "continue in the next cabinet `c.cab` are not joined: `middle.bin`",
    );
}

#[test]
fn continued_files_need_the_neighbor_the_header_names() {
    let files = vec![FileSpec {
        name: b"x".to_vec(),
        size: 10,
        offset: 0,
        folder: CONTINUED_TO_NEXT,
        attributes: 0,
    }];
    let built = Cabinet::new(vec![stored(&[0; 10])], files).build();
    let e = parse_error(&built.bytes);
    assert!(
        e.contains("`x` continues in a next cabinet that the header does not name"),
        "{e}"
    );
    let files = vec![FileSpec {
        name: b"x".to_vec(),
        size: 10,
        offset: 0,
        folder: CONTINUED_FROM_PREV,
        attributes: 0,
    }];
    let built = Cabinet::new(vec![stored(&[0; 10])], files).build();
    let e = parse_error(&built.bytes);
    assert!(
        e.contains("continues from a previous cabinet that the header does not name"),
        "{e}"
    );
    // A split block outside a folder that continues in the next cabinet.
    let mut folder = stored(&[0; 10]);
    folder.blocks[0].uncompressed = 0;
    let (files, _) = pack(0, &[("x", &[0; 10])]);
    let e = parse_error(&Cabinet::new(vec![folder], files).build().bytes);
    assert!(
        e.contains("cbUncomp 0 outside a block that continues in the next cabinet"),
        "{e}"
    );
}

#[test]
fn signed_cabinets_report_the_signature_as_not_verified() {
    let mut cabinet = stored_cabinet();
    // osslsigncode's reserve: 0x00100000, signature offset and size, 8
    // zero bytes; the signature follows the cabinet.
    let signature = vec![0x30, 0x82, 0x01, 0x00, 0xAB, 0xCD];
    let mut header = vec![0u8; 20];
    header[..4].copy_from_slice(&0x0010_0000u32.to_le_bytes());
    cabinet.reserve = Some(Reserve {
        header,
        folder: 0,
        data: 0,
    });
    let unsigned = cabinet.build();
    let end = unsigned.bytes.len();
    let mut reserve = cabinet.reserve.clone().unwrap();
    reserve.header[4..8].copy_from_slice(&(end as u32).to_le_bytes());
    reserve.header[8..12].copy_from_slice(&(signature.len() as u32).to_le_bytes());
    cabinet.reserve = Some(reserve);
    let mut bytes = cabinet.build().bytes;
    bytes.extend_from_slice(&signature);
    let c = parse(&bytes);
    assert_eq!(c.consumed, bytes.len());
    assert_note(
        &c,
        &format!("Authenticode signature present (6 B at 0x{end:X}); not verified"),
    );
    assert_eq!(labels(&c), ["bin\\tool", "bin\\driver.sys"]);
    // Without the signature bytes, the reserve is application data and the
    // cabinet ends at cbCabinet.
    let c = parse(&bytes[..end]);
    assert!(!c.notes.iter().any(|n| n.contains("Authenticode")));
}

#[test]
fn reserve_areas_are_skipped_and_outside_the_checksum() {
    let mut cabinet = stored_cabinet();
    cabinet.reserve = Some(Reserve {
        header: b"application data".to_vec(),
        folder: 3,
        data: 5,
    });
    let built = cabinet.build();
    assert_eq!(built.data_header, CFDATA_SIZE + 5);
    let c = parse(&built.bytes);
    assert_eq!(labels(&c), ["bin\\tool", "bin\\driver.sys"]);
    assert_eq!(
        child(&c, "bin\\tool").offset,
        built.data_at(0, 0) + README.len()
    );
    assert_note(&c, "CFDATA checksums verified for 1 of 1 blocks");
    let p = classify(&built.bytes);
    assert_eq!(metadata(&p, "cab_header_reserve").to_string(), "16");
    assert_eq!(metadata(&p, "cab_flags").to_string(), "0x0004");
}

#[test]
fn header_details_are_noted() {
    let mut cabinet = stored_cabinet();
    cabinet.version = [2, 1];
    cabinet.extra_flags = 0x0010;
    cabinet.table_gap = 6;
    cabinet.files[1].attributes |= A_EXEC;
    cabinet.files[2].name = "bin\\caf\u{e9}.sys".as_bytes().to_vec();
    cabinet.files[2].attributes |= A_NAME_IS_UTF;
    cabinet.files[0].name = b"read\xe9.txt".to_vec();
    let built = cabinet.build();
    let c = parse(&built.bytes);
    assert_note(
        &c,
        "The cabinet declares format version 1.2; the specification describes 1.3",
    );
    assert_note(&c, "Reserved CFHEADER flag bits 0x0010 are set");
    assert_note(
        &c,
        &format!(
            "6 B between the CFFOLDER table and the CFFILE table at 0x{:X}",
            built.files_offset
        ),
    );
    assert_note(
        &c,
        "Files marked to run after extraction (_A_EXEC): `bin\\tool`",
    );
    assert_note(
        &c,
        "1 file name is in an unspecified code page (no _A_NAME_IS_UTF)",
    );
    assert_eq!(labels(&c), ["bin\\tool", "bin\\caf\u{e9}.sys"]);
}

#[test]
fn corrupted_structures_are_parse_errors() {
    let built = stored_cabinet().build();
    let image = &built.bytes;
    let with = |at: usize, value: &[u8]| {
        let mut changed = image.clone();
        changed[at..at + value.len()].copy_from_slice(value);
        changed
    };
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (with(0, b"MSCX"), "Missing cabinet signature MSCF at 0x0"),
        (
            with(4, &[1]),
            "Invalid CFHEADER reserved1 0x1 at 0x4: it must be zero",
        ),
        (
            with(0x14, &[0, 0, 0, 1]),
            "Invalid CFHEADER reserved3 0x1000000 at 0x14",
        ),
        (with(8, &[0x10, 0, 0, 0]), "Invalid cbCabinet 16 B at 0x8"),
        (
            with(8, &((image.len() + 1) as u32).to_le_bytes()),
            "Truncated cabinet: ",
        ),
        (
            with(0x1A, &[0, 0]),
            "the cabinet has no folders (cFolders 0)",
        ),
        (with(0x1C, &[0, 0]), "the cabinet has no files (cFiles 0)"),
        (
            with(0x10, &[0x28, 0, 0, 0]),
            "Invalid coffFiles 0x28 at 0x10",
        ),
        (
            with(built.files_offset + 8, &[1, 0]),
            "Invalid CFFILE iFolder 1 at 0x",
        ),
        (with(0x1C, &[0xFF, 0x0F]), "Truncated CFFILE table at 0x"),
        (
            with(0x24, &[0xFF, 0xFF, 0xFF, 0x7F]),
            "Truncated CFDATA chain of folder 0 at 0x7FFFFFFF",
        ),
        (with(0x28, &[2, 0]), "Truncated CFDATA at 0x"),
    ];
    for (data, expected) in cases {
        let e = parse_error(&data);
        assert!(e.starts_with("Cabinet parse error: "), "{e}");
        assert!(e.contains(expected), "expected {expected:?} in {e:?}");
    }
    // A stored block whose sizes differ, and cbUncomp over 32 KiB.
    let block = built.blocks[0][0];
    let e = parse_error(&with(block + 6, &[0x10, 0]));
    assert!(e.contains("B declares 16 B uncompressed"), "{e}");
    let e = parse_error(&with(block + 6, &[0x01, 0x80]));
    assert!(e.contains("cbUncomp 32769 B exceeds 32 KiB"), "{e}");
    // A name without its NUL in the cabinet, and an empty name.
    let name_at = built.files_offset + CFFILE_SIZE;
    let mut unterminated = image[..name_at + 4].to_vec();
    unterminated[8..12].copy_from_slice(&((name_at + 4) as u32).to_le_bytes());
    unterminated[0x1C..0x1E].copy_from_slice(&1u16.to_le_bytes());
    let e = parse_error(&unterminated);
    assert!(e.contains("Invalid CFFILE szName at 0x"), "{e}");
    let e = parse_error(&with(name_at, &[0]));
    assert!(
        e.contains(&format!("Invalid CFFILE szName at 0x{name_at:X}: empty")),
        "{e}"
    );
}

#[test]
fn overlapping_folders_are_parse_errors() {
    let (mut files, data) = pack(0, &[("a.elf", &elf(100, 1))]);
    files.push(FileSpec {
        name: b"b.elf".to_vec(),
        size: 100,
        offset: 0,
        folder: 1,
        attributes: 0,
    });
    let built = Cabinet::new(vec![stored(&data), stored(&data)], files).build();
    let mut image = built.bytes.clone();
    // Point folder 1 at folder 0's block.
    let folder1 = CFHEADER_SIZE + CFFOLDER_SIZE;
    image[folder1..folder1 + 4].copy_from_slice(&(built.blocks[0][0] as u32).to_le_bytes());
    let e = parse_error(&image);
    assert!(
        e.contains("Invalid CFFOLDER 1 at 0x2C: its CFDATA blocks at 0x"),
        "{e}"
    );
    assert!(e.contains("overlap those of folder 0"), "{e}");
}

#[test]
fn data_after_the_cabinet_is_padding_another_format_or_an_error() {
    let image = stored_cabinet().build().bytes;
    let mut padded = image.clone();
    padded.extend_from_slice(&[0xFF; 9]);
    let c = parse(&padded);
    assert_note(&c, "9 bytes of padding after the cabinet");
    let mut followed = image.clone();
    followed.extend_from_slice(&elf(64, 0));
    let c = parse(&followed);
    assert_eq!(child(&c, "Data after the cabinet").offset, image.len());
    let mut junk = image.clone();
    junk.extend_from_slice(b"junk");
    let e = parse_error(&junk);
    assert!(
        e.contains(&format!(
            "Unexpected data after the cabinet at 0x{:X}",
            image.len()
        )),
        "{e}"
    );
}

#[test]
fn nested_cabinets_are_classified_as_members() {
    let inner = stored_cabinet().build().bytes;
    let (files, data) = pack(0, &[("inner.cab", &inner)]);
    let outer = Cabinet::new(vec![mszip(&data)], files).build();
    let p = classify(&outer.bytes);
    assert_eq!(p.format.format, FileFormat::MsCab);
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_eq!(p.slices[0].label.as_deref(), Some("inner.cab"));
}

#[test]
fn listing_stops_at_the_component_limit() {
    let member = elf(64, 0);
    let names: Vec<String> = (0..MAX_COMPONENTS + 3)
        .map(|i| format!("m{i}.elf"))
        .collect();
    let members: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &member[..])).collect();
    let (files, data) = pack(0, &members);
    let built = Cabinet::new(vec![mszip(&data)], files).build();
    let c = parse(&built.bytes);
    assert_eq!(c.children.len(), MAX_COMPONENTS);
    assert_note(
        &c,
        "File listing stopped at 4096 files; 3 further files were not examined",
    );
}

#[test]
fn folders_decode_only_up_to_the_payload_limit() {
    // 65 MiB of zeros in one MSZIP folder: a 64-byte ELF at offset 0 and
    // one at 65 MiB - 64, past the 64 MiB a folder may decode to.
    let size = 65 << 20;
    let mut data = vec![0u8; size];
    data[..64].copy_from_slice(&elf(64, 0));
    data[size - 64..].copy_from_slice(&elf(64, 0));
    let files = vec![
        FileSpec {
            name: b"first.elf".to_vec(),
            size: 64,
            offset: 0,
            folder: 0,
            attributes: 0,
        },
        FileSpec {
            name: b"last.elf".to_vec(),
            size: 64,
            offset: (size - 64) as u32,
            folder: 0,
            attributes: 0,
        },
    ];
    let built = Cabinet::new(vec![mszip(&data)], files).build();
    let c = parse(&built.bytes);
    assert_eq!(labels(&c), ["first.elf"]);
    assert_note(&c, "Files over the extraction limits (64 MiB per folder or file, 256 MiB per cabinet) were not decoded or classified: `last.elf`");
}

#[test]
fn the_largest_tables_parse_with_bounded_metadata() {
    // 65,533 empty folders (the folder indices below 0xFFFD) and 65,535
    // empty files spread over them.
    let folder_count = usize::from(CONTINUED_FROM_PREV);
    let folders = vec![
        FolderSpec {
            type_compress: TYPE_NONE,
            blocks: Vec::new(),
        };
        folder_count
    ];
    let files = (0..usize::from(u16::MAX))
        .map(|i| FileSpec {
            name: b"f".to_vec(),
            size: 0,
            offset: 0,
            folder: (i % folder_count) as u16,
            attributes: 0,
        })
        .collect();
    let built = Cabinet::new(folders, files).build();
    let c = parse(&built.bytes);
    assert!(c.children.is_empty());
    assert_note(&c, "65535 empty files are not examined");
    assert_note(
        &c,
        "Folder metadata describes the first 64 of 65533 folders",
    );
    assert!(
        c.metadata.len() < 100,
        "{} metadata entries",
        c.metadata.len()
    );
}

#[test]
fn files_past_their_folder_data_are_noted() {
    let (mut files, data) = pack(0, &[("a.elf", &elf(100, 1))]);
    files[0].size = 101;
    let built = Cabinet::new(vec![stored(&data)], files).build();
    let c = parse(&built.bytes);
    assert!(c.children.is_empty());
    assert_note(
        &c,
        "Files that extend past their folder's data were not extracted: `a.elf`",
    );
}

/// Fixtures for the sweeps: stored, MSZIP and LZX cabinets.
fn sweep_fixtures() -> Vec<Vec<u8>> {
    let stored = stored_cabinet().build().bytes;
    let (files, data) = pack(0, &[("a.elf", &elf(3000, 7)), ("b.txt", README)]);
    let zipped = Cabinet::new(vec![mszip(&data)], files).build().bytes;
    let stream = lzx::encode(
        15,
        Some(0x10000),
        &[
            Block::Verbatim(lzx::literals(&elf(64, 0))),
            Block::Aligned(vec![
                Token::Literal(1),
                Token::Match {
                    length: 40,
                    offset: 33,
                },
                Token::Match {
                    length: 3,
                    offset: 1,
                },
            ]),
            Block::Uncompressed(b"odd".to_vec()),
        ],
    );
    let files = vec![FileSpec {
        name: b"l.elf".to_vec(),
        size: stream.window.len() as u32,
        offset: 0,
        folder: 0,
        attributes: 0,
    }];
    let packed = Cabinet::new(vec![lzx_folder(15, &stream)], files)
        .build()
        .bytes;
    vec![stored, zipped, packed]
}

#[test]
fn every_prefix_is_an_error_or_not_a_cabinet() {
    for image in sweep_fixtures() {
        assert!(!parse(&image).children.is_empty());
        for end in 0..image.len() {
            let prefix = &image[..end];
            assert!(
                cab::parse_container(prefix, Layout::Cabinet).is_err(),
                "prefix of {end} B parses"
            );
            if end >= CFHEADER_SIZE {
                assert_eq!(
                    cab::detect(prefix),
                    Some(Layout::Cabinet),
                    "prefix of {end} B"
                );
                assert!(detect_payload(prefix, &ClassifierOptions::new()).is_err());
            }
        }
    }
}

#[test]
fn byte_mutations_never_panic() {
    for image in sweep_fixtures() {
        for i in 0..image.len() {
            for value in [0x00, 0xFF, image[i] ^ 0x01] {
                let mut mutated = image.clone();
                mutated[i] = value;
                let _ = cab::parse_container(&mutated, Layout::Cabinet);
                if i % 7 == 0 {
                    let _ = detect_payload(&mutated, &ClassifierOptions::new());
                }
            }
        }
    }
}

#[test]
fn real_cabinets_from_cab_samples_dir() {
    let Ok(dir) = std::env::var("CAB_SAMPLES_DIR") else {
        eprintln!("CAB_SAMPLES_DIR is not set; skipped");
        return;
    };
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).expect("CAB_SAMPLES_DIR is a directory") {
        let path = entry.unwrap().path();
        let Ok(data) = std::fs::read(&path) else {
            continue;
        };
        if !data.starts_with(b"MSCF") {
            continue;
        }
        seen += 1;
        let c = cab::parse_container(&data, Layout::Cabinet)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert!(
            !c.notes
                .iter()
                .any(|n| n.contains("not match") || n.contains("not extracted")),
            "{}: {:#?}",
            path.display(),
            c.notes
        );
        let p = classify(&data);
        assert_eq!(p.format.format, FileFormat::MsCab, "{}", path.display());
        eprintln!(
            "{}: {} children, primary {}; {:?}",
            path.display(),
            c.children.len(),
            p.primary.isa,
            c.notes
        );
    }
    assert!(seen > 0, "no cabinets in {dir}");
}
