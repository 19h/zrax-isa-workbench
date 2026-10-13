//! Psy-Q (SN Systems) LNK object files: the record stream (sections, BYTES,
//! ZEROES, relocations and their expressions, symbols, debug records), the
//! PROGRAMTYPE record as the target field, `.text` sections as code
//! children and other sections as opaque children, record errors, and
//! truncation and mutation sweeps. Real objects are read from
//! `IDA_INPUT_DIR` when it is set.

use std::path::PathBuf;
use zrax::formats::psyq;
use zrax::{
    detect_payload, ClassificationSource, ClassifierOptions, ContainedArch, DetectionPayload,
    Endianness, FileFormat, Isa, MetadataKey,
};

/// Compiled little-endian MIPS32 code from the repository's testbins.
const MIPS_LE_CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testbins/mips32_le_mipsel-unknown-linux-gnu_O0_call_nested.bin"
);
/// The same program compiled big-endian.
const MIPS_BE_CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testbins/mips32_be_mips-unknown-linux-gnu_O0_call_nested.bin"
);

// Record opcodes (PCSX-Redux `PsyqOpcode`; `GROUP_SYMBOL` from psy-k).
const END: u8 = 0;
const BYTES: u8 = 2;
const SWITCH: u8 = 6;
const ZEROES: u8 = 8;
const RELOCATION: u8 = 10;
const EXPORTED_SYMBOL: u8 = 12;
const IMPORTED_SYMBOL: u8 = 14;
const SECTION: u8 = 16;
const LOCAL_SYMBOL: u8 = 18;
const GROUP_SYMBOL: u8 = 20;
const FILENAME: u8 = 28;
const PROGRAMTYPE: u8 = 46;
const UNINITIALIZED: u8 = 48;
const INC_SLD_LINENUM_BY_WORD: u8 = 54;
const END_SLD: u8 = 60;
const FUNCTION: u8 = 74;
const FUNCTION_END: u8 = 76;
const SECTION_DEF2: u8 = 84;

// Relocation types (PCSX-Redux `PsyqRelocType`).
const REL26: u8 = 74;
const HI16: u8 = 82;
const LO16: u8 = 84;

// Expression operators (PCSX-Redux `PsyqExprOpcode`).
const EXPR_CONSTANT: u8 = 0;
const EXPR_SYMBOL: u8 = 2;
const EXPR_SECTION_BASE: u8 = 4;
const EXPR_ADD: u8 = 44;

// Processor types (psy-k `cputype`).
const MOTOROLA_68000: u8 = 0;
const MIPS_R3000: u8 = 7;
const HITACHI_SH2: u8 = 8;
/// Accepted by PCSX-Redux, but no source names its processor.
const UNDOCUMENTED_TYPE: u8 = 9;

// Section IDs of the synthetic objects.
const RDATA: u16 = 1;
const TEXT: u16 = 2;
const DATA: u16 = 3;
const BSS: u16 = 4;

const TEXT_LABEL: &str = ".text (section 0x0002)";
const DATA_LABEL: &str = ".data (section 0x0003)";

fn mips_le_code() -> Vec<u8> {
    std::fs::read(MIPS_LE_CODE).expect("testbin is committed")
}

fn mips_be_code() -> Vec<u8> {
    std::fs::read(MIPS_BE_CODE).expect("testbin is committed")
}

/// Builds an LNK object from the documented records: `LNK`, version 2,
/// then each record as a one-byte opcode and its little-endian body.
/// Strings are a length byte and the bytes.
struct Lnk {
    bytes: Vec<u8>,
}

impl Lnk {
    fn new() -> Self {
        let mut bytes = b"LNK".to_vec();
        bytes.push(2);
        Self { bytes }
    }

    /// File offset of the next record.
    fn offset(&self) -> usize {
        self.bytes.len()
    }

    fn u8(&mut self, value: u8) -> &mut Self {
        self.bytes.push(value);
        self
    }

    fn u16(&mut self, value: u16) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    fn u32(&mut self, value: u32) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    fn string(&mut self, text: &str) -> &mut Self {
        self.u8(u8::try_from(text.len()).expect("short test name"));
        self.bytes.extend_from_slice(text.as_bytes());
        self
    }

    /// PROGRAMTYPE: u8 processor type.
    fn processor(&mut self, processor: u8) -> &mut Self {
        self.u8(PROGRAMTYPE).u8(processor)
    }

    /// SECTION: u16 ID, u16 group 0, u8 alignment 8, name.
    fn section(&mut self, id: u16, name: &str) -> &mut Self {
        self.u8(SECTION).u16(id).u16(0).u8(8).string(name)
    }

    /// SWITCH: u16 section ID.
    fn switch(&mut self, id: u16) -> &mut Self {
        self.u8(SWITCH).u16(id)
    }

    /// BYTES: u16 size and the bytes. Returns the payload's file offset.
    fn code(&mut self, payload: &[u8]) -> usize {
        self.u8(BYTES)
            .u16(u16::try_from(payload.len()).expect("BYTES payload fits u16"));
        let offset = self.offset();
        self.bytes.extend_from_slice(payload);
        offset
    }

    /// ZEROES: u32 size of zero fill.
    fn zeroes(&mut self, size: u32) -> &mut Self {
        self.u8(ZEROES).u32(size)
    }

    /// RELOCATION: u8 type, u16 offset in the section, expression.
    fn relocation(&mut self, kind: u8, offset: u16, expression: &[u8]) -> &mut Self {
        self.u8(RELOCATION).u8(kind).u16(offset);
        self.bytes.extend_from_slice(expression);
        self
    }

    /// EXPORTED_SYMBOL: u16 symbol, u16 section, u32 offset, name.
    fn export(&mut self, symbol: u16, section: u16, offset: u32, name: &str) -> &mut Self {
        self.u8(EXPORTED_SYMBOL)
            .u16(symbol)
            .u16(section)
            .u32(offset)
            .string(name)
    }

    /// IMPORTED_SYMBOL: u16 symbol, name.
    fn import(&mut self, symbol: u16, name: &str) -> &mut Self {
        self.u8(IMPORTED_SYMBOL).u16(symbol).string(name)
    }

    /// LOCAL_SYMBOL: u16 section, u32 offset, name.
    fn local(&mut self, section: u16, offset: u32, name: &str) -> &mut Self {
        self.u8(LOCAL_SYMBOL).u16(section).u32(offset).string(name)
    }

    /// UNINITIALIZED: u16 symbol, u16 section, u32 size, name.
    fn uninitialized(&mut self, symbol: u16, section: u16, size: u32, name: &str) -> &mut Self {
        self.u8(UNINITIALIZED)
            .u16(symbol)
            .u16(section)
            .u32(size)
            .string(name)
    }

    /// FILENAME: u16 file number, name.
    fn filename(&mut self, number: u16, name: &str) -> &mut Self {
        self.u8(FILENAME).u16(number).string(name)
    }

    /// FUNCTION: u16 section, u32 offset, u16 file, u32 line, u16 frame
    /// register (29, `sp`), u32 frame size, u16 return register (31,
    /// `ra`), u32 mask, u32 mask offset, name.
    fn function(&mut self, section: u16, offset: u32, name: &str) -> &mut Self {
        self.u8(FUNCTION)
            .u16(section)
            .u32(offset)
            .u16(9)
            .u32(1)
            .u16(29)
            .u32(24)
            .u16(31)
            .u32(0x8000_0000)
            .u32(0xFFFF_FFF8)
            .string(name)
    }

    /// FUNCTION_END: u16 section, u32 offset, u32 line.
    fn function_end(&mut self, section: u16, offset: u32) -> &mut Self {
        self.u8(FUNCTION_END).u16(section).u32(offset).u32(12)
    }

    /// END, and the finished file.
    fn end(&mut self) -> Vec<u8> {
        self.u8(END);
        std::mem::take(&mut self.bytes)
    }
}

/// `(sectbase(section) + addend)`.
fn section_plus(section: u16, addend: u32) -> Vec<u8> {
    let mut expression = vec![EXPR_ADD, EXPR_SECTION_BASE];
    expression.extend_from_slice(&section.to_le_bytes());
    expression.push(EXPR_CONSTANT);
    expression.extend_from_slice(&addend.to_le_bytes());
    expression
}

/// `[symbol]`, the address of a symbol.
fn symbol_address(symbol: u16) -> Vec<u8> {
    let mut expression = vec![EXPR_SYMBOL];
    expression.extend_from_slice(&symbol.to_le_bytes());
    expression
}

/// A synthetic object and the file coordinates of its section bytes.
struct Object {
    file: Vec<u8>,
    /// File offsets of the two `.text` BYTES payloads.
    text_offsets: [usize; 2],
    data_offset: usize,
}

const DATA_BYTES: &[u8] = b"Hello, PlayStation\0\0";

/// A `PlayStation`-style object as `ccpsx` lays it out: PROGRAMTYPE;
/// sections `.rdata`, `.text`, `.data`, `.bss`; the source file; `code` in
/// two BYTES records with a HI16/LO16 pair and a REL26 after the first;
/// `.data` bytes; 16 B of `.bss` zero fill; symbols; function debug
/// records; END.
fn object(processor: Option<u8>, code: &[u8]) -> Object {
    let mut lnk = Lnk::new();
    if let Some(processor) = processor {
        lnk.processor(processor);
    }
    lnk.section(RDATA, ".rdata")
        .section(TEXT, ".text")
        .section(DATA, ".data")
        .section(BSS, ".bss")
        .filename(5, "C:\\PSX\\SRC\\MAIN.C")
        .switch(TEXT);
    let (first, second) = code.split_at(code.len() / 2);
    let first_offset = lnk.code(first);
    lnk.relocation(HI16, 0x10, &section_plus(DATA, 0))
        .relocation(LO16, 0x14, &section_plus(DATA, 0))
        .relocation(REL26, 0x18, &symbol_address(7))
        .u8(END_SLD)
        .u16(0)
        .switch(DATA);
    let data_offset = lnk.code(DATA_BYTES);
    lnk.switch(BSS).zeroes(16).switch(TEXT);
    let second_offset = lnk.code(second);
    lnk.import(7, "printf")
        .export(6, TEXT, 0, "main")
        .local(DATA, 0, "greeting")
        .uninitialized(8, BSS, 4, "counter")
        .function(TEXT, 0, "main")
        .function_end(TEXT, 0x40);
    Object {
        file: lnk.end(),
        text_offsets: [first_offset, second_offset],
        data_offset,
    }
}

/// An object whose only section is `.text`, written in one BYTES record.
fn single_record_object(processor: u8, code: &[u8]) -> (Vec<u8>, usize) {
    let mut lnk = Lnk::new();
    lnk.processor(processor).section(TEXT, ".text").switch(TEXT);
    let offset = lnk.code(code);
    (lnk.end(), offset)
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn error_text(data: &[u8]) -> String {
    match detect_payload(data, &ClassifierOptions::new()) {
        Ok(p) => panic!("expected an error, got {:?}", p.format.format),
        Err(e) => e.to_string(),
    }
}

/// Whether `data` is reported as a Psy-Q object, or fails as one.
fn is_claimed(data: &[u8]) -> bool {
    match detect_payload(data, &ClassifierOptions::new()) {
        Ok(p) => p.format.format == FileFormat::PsyqObject,
        Err(e) => e.to_string().starts_with("PsyQ object parse error"),
    }
}

fn has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(text))
}

fn metadata(p: &DetectionPayload, key: &str) -> Option<String> {
    p.metadata
        .iter()
        .find(|m| matches!(&m.key, MetadataKey::Custom(k) if k == key))
        .map(|m| m.value.to_string())
}

fn slice<'a>(p: &'a DetectionPayload, label: &str) -> &'a ContainedArch {
    p.slices
        .iter()
        .find(|s| s.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("slice {label} in {:?}", p.slices))
}

#[test]
fn r3000_objects_report_little_endian_mips_with_text_as_code() {
    let code = mips_le_code();
    let o = object(Some(MIPS_R3000), &code);
    let p = classify(&o.file);
    assert_eq!(p.format.format, FileFormat::PsyqObject);
    assert_eq!(p.format.variant_name.as_deref(), Some("PsyQ LNK object"));
    assert_eq!(
        (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
        (Isa::Mips, 32, Endianness::Little)
    );
    assert_eq!(p.primary.source, ClassificationSource::FileFormat);
    assert!((p.primary.confidence - 1.0).abs() < f64::EPSILON);

    // `.text` spans both BYTES records in the file; its decoded bytes are
    // the two payloads concatenated.
    let text = slice(&p, TEXT_LABEL);
    let second_half = code.len() - code.len() / 2;
    let stored_end = o.text_offsets[1] + second_half;
    assert_eq!((text.isa, text.endianness), (Isa::Mips, Endianness::Little));
    assert_eq!(text.offset, o.text_offsets[0] as u64);
    assert_eq!(text.size, (stored_end - o.text_offsets[0]) as u64);
    let decoded = text.decoded.as_ref().expect("reassembled section");
    assert_eq!(decoded.transform, "LNK BYTES records");
    assert_eq!((decoded.offset, decoded.size), (0, code.len() as u64));
    assert_eq!(
        text.variant.as_ref().map(|v| v.name.as_str()),
        Some("R3000")
    );

    // `.data` is listed as opaque data; `.rdata` and `.bss` hold no bytes.
    let data = slice(&p, DATA_LABEL);
    assert!(matches!(data.isa, Isa::Unknown(_)));
    assert_eq!(
        (data.offset, data.size),
        (o.data_offset as u64, DATA_BYTES.len() as u64)
    );
    assert_eq!(data.decoded, None);
    assert_eq!(p.slices.len(), 2);
    assert!(has_note(&p, ".data (section 0x0003): opaque"));

    let messages: Vec<&str> = p.notes.iter().map(|n| n.message.as_str()).collect();
    let expected = [
        "LNK version 2 object; processor type 7: MIPS R3000 (PlayStation)",
        &format!(
            "4 sections: .rdata, .text ({} B), .data (20 B), .bss (16 B zero fill)",
            code.len()
        ),
        "Section contents are the BYTES records as stored; 3 relocations are not applied and \
         zero fill is not materialized",
        "1 exported symbol: main",
        "1 imported symbol: printf",
        "1 local symbol: greeting",
        "1 uninitialized symbol: counter",
        "1 function in debug records: main",
        "1 source file: C:\\PSX\\SRC\\MAIN.C",
    ];
    for note in expected {
        assert!(messages.contains(&note), "{note} in {messages:?}");
    }
    assert_eq!(metadata(&p, "psyq_version").as_deref(), Some("2"));
    assert_eq!(metadata(&p, "psyq_processor_type").as_deref(), Some("7"));
    assert_eq!(metadata(&p, "psyq_sections").as_deref(), Some("4"));
    assert_eq!(metadata(&p, "psyq_relocations").as_deref(), Some("3"));
    assert_eq!(
        metadata(&p, "psyq_image_size"),
        Some(o.file.len().to_string())
    );
}

#[test]
fn single_record_sections_keep_their_stored_bytes() {
    let code = mips_le_code();
    let (file, offset) = single_record_object(MIPS_R3000, &code);
    let p = classify(&file);
    let text = slice(&p, TEXT_LABEL);
    assert_eq!(text.decoded, None);
    assert_eq!((text.offset, text.size), (offset as u64, code.len() as u64));
    assert_eq!(text.isa, Isa::Mips);
}

#[test]
fn sh2_and_68000_processor_types_name_big_endian_targets() {
    // SH-2 `rts; nop` and 68000 `nop; rts`, big-endian.
    let sh2 = [0x00, 0x0B, 0x00, 0x09].repeat(16);
    let m68k = [0x4E, 0x71, 0x4E, 0x75].repeat(16);
    for (processor, code, isa, variant, name) in [
        (HITACHI_SH2, sh2, Isa::Sh, "SH-2", "Hitachi SH-2 (Saturn)"),
        (MOTOROLA_68000, m68k, Isa::M68k, "68000", "Motorola 68000"),
    ] {
        let (file, _) = single_record_object(processor, &code);
        let p = classify(&file);
        assert_eq!(
            (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
            (isa, 32, Endianness::Big),
            "{name}"
        );
        let text = slice(&p, TEXT_LABEL);
        assert_eq!(
            (text.isa, text.endianness),
            (isa, Endianness::Big),
            "{name}"
        );
        assert_eq!(
            text.variant.as_ref().map(|v| v.name.as_str()),
            Some(variant)
        );
        assert!(has_note(
            &p,
            &format!("LNK version 2 object; processor type {processor}: {name}")
        ));
    }
}

#[test]
fn undocumented_or_missing_processor_types_leave_the_isa_to_the_code() {
    let o = object(Some(UNDOCUMENTED_TYPE), &mips_be_code());
    let p = classify(&o.file);
    assert_eq!(p.format.format, FileFormat::PsyqObject);
    assert_eq!(
        (p.primary.isa, p.primary.endianness),
        (Isa::Mips, Endianness::Big)
    );
    assert_ne!(p.primary.source, ClassificationSource::FileFormat);
    assert!(has_note(
        &p,
        "LNK version 2 object; processor type 9 is not documented, so the ISA is not encoded"
    ));
    assert!(has_note(
        &p,
        &format!("Primary ISA selected from {TEXT_LABEL}")
    ));
    assert_eq!(slice(&p, TEXT_LABEL).variant, None);

    let o = object(None, &mips_le_code());
    let p = classify(&o.file);
    assert_eq!(
        (p.primary.isa, p.primary.endianness),
        (Isa::Mips, Endianness::Little)
    );
    assert!(has_note(
        &p,
        "LNK version 2 object; no PROGRAMTYPE record, so the processor is not encoded"
    ));
    assert_eq!(metadata(&p, "psyq_processor_type"), None);
}

#[test]
fn objects_without_text_bytes_report_the_processor_and_no_code() {
    let mut lnk = Lnk::new();
    lnk.processor(MIPS_R3000)
        .section(TEXT, ".text")
        .section(DATA, ".data")
        .switch(DATA);
    lnk.code(DATA_BYTES);
    let p = classify(&lnk.end());
    assert_eq!(p.primary.isa, Isa::Mips);
    assert!(has_note(
        &p,
        "No code: no .text section holds BYTES records"
    ));
    assert_eq!(p.slices.len(), 1);
    assert!(matches!(slice(&p, DATA_LABEL).isa, Isa::Unknown(_)));
}

#[test]
fn group_symbols_and_empty_objects_parse() {
    // psy-k's Saturn objects declare a group before its section.
    let mut lnk = Lnk::new();
    lnk.processor(HITACHI_SH2)
        .u8(GROUP_SYMBOL)
        .u16(0x330B)
        .u8(0x80)
        .string("bss")
        .section(0x330C, "bssend")
        .switch(0x330C)
        .export(0x330A, 0x330C, 0, "end");
    let p = classify(&lnk.end());
    assert_eq!(p.format.format, FileFormat::PsyqObject);
    assert_eq!(p.primary.isa, Isa::Sh);
    assert!(has_note(&p, "1 section: bssend"));

    let p = classify(&Lnk::new().end());
    assert_eq!(p.format.format, FileFormat::PsyqObject);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(has_note(&p, "No sections are declared"));
}

#[test]
fn padding_after_end_is_noted_and_other_bytes_are_errors() {
    let mut file = object(Some(MIPS_R3000), &mips_le_code()).file;
    let end = file.len() - 1;
    file.extend_from_slice(&[0xFF; 32]);
    let p = classify(&file);
    assert!(has_note(&p, "32 B of padding after the END record"));
    file.push(0x12);
    assert_eq!(
        error_text(&file),
        format!("PsyQ object parse error: Unexpected 33 B after the END record at 0x{end:X}")
    );
}

/// The object up to its sections and SWITCH to `.text`, for error cases.
fn prologue() -> Lnk {
    let mut lnk = Lnk::new();
    lnk.processor(MIPS_R3000)
        .section(TEXT, ".text")
        .section(BSS, ".bss")
        .switch(TEXT);
    lnk
}

#[test]
fn record_errors_name_the_record_and_its_offset() {
    let mut cases: Vec<(Vec<u8>, String)> = Vec::new();

    let mut lnk = prologue();
    let at = lnk.offset();
    cases.push((
        lnk.u8(117).end(),
        format!("Unknown record opcode 117 at 0x{at:X}"),
    ));

    let mut lnk = prologue();
    let at = lnk.offset();
    let file = lnk.u8(INC_SLD_LINENUM_BY_WORD).u16(0).u16(1).end();
    cases.push((
        file,
        format!("Unsupported record 54 at 0x{at:X}: its layout is not confirmed"),
    ));

    // SECTION_DEF2 with one dimension: the readers disagree on its size.
    // Fields: u16 section, u32 value, u16 class, u16 type, u32 size, u16
    // dimension count 1, one dimension (8), tag, name.
    let mut lnk = prologue();
    let at = lnk.offset();
    lnk.u8(SECTION_DEF2)
        .u16(TEXT)
        .u32(0)
        .u16(2)
        .u16(0x34)
        .u32(4);
    let file = lnk.u16(1).u16(8).string("").string("table").end();
    cases.push((
        file,
        format!(
            "Unsupported SECTION_DEF2 record at 0x{at:X}: 1 dimensions; their encoding is not \
             confirmed"
        ),
    ));

    let mut lnk = prologue();
    let at = lnk.offset();
    cases.push((
        lnk.processor(MIPS_R3000).end(),
        format!("Duplicate PROGRAMTYPE record at 0x{at:X}"),
    ));

    let mut lnk = prologue();
    let at = lnk.offset();
    cases.push((
        lnk.section(TEXT, ".text2").end(),
        format!("Duplicate section 0x0002 in the SECTION record at 0x{at:X}"),
    ));

    let mut lnk = prologue();
    let at = lnk.offset();
    let file = lnk.u8(SECTION).u16(9).u16(0).u8(3).string(".odd").end();
    cases.push((
        file,
        format!("Invalid SECTION record at 0x{at:X}: alignment 3 is not a power of two"),
    ));

    let mut lnk = Lnk::new();
    lnk.section(TEXT, ".text");
    let at = lnk.offset();
    lnk.code(&[0; 4]);
    cases.push((
        lnk.end(),
        format!("Missing SWITCH record before the BYTES record at 0x{at:X}"),
    ));

    let mut lnk = prologue();
    lnk.switch(0x77);
    let at = lnk.offset();
    cases.push((
        lnk.zeroes(4).end(),
        format!("Unknown section 0x0077 selected for the ZEROES record at 0x{at:X}"),
    ));

    let mut lnk = prologue();
    let at = lnk.offset();
    cases.push((
        lnk.uninitialized(1, 0x55, 4, "x").end(),
        format!("Unknown section 0x0055 in the UNINITIALIZED record at 0x{at:X}"),
    ));

    // `bank(1)` (psy-k marks it untested) and an operator no reader has.
    for (operator, text) in [(6, "Unsupported"), (1, "Unknown")] {
        let mut lnk = prologue();
        let at = lnk.offset() + 4;
        let file = lnk.relocation(HI16, 0, &[operator, 1, 0]).end();
        cases.push((
            file,
            format!("{text} relocation expression operator {operator} at 0x{at:X}"),
        ));
    }

    let mut lnk = prologue();
    let missing_end = lnk.offset();
    let mut file = lnk.end();
    file.pop();
    cases.push((
        file,
        format!(
            "Truncated record stream: no END record before the end of the file at \
             0x{missing_end:X}"
        ),
    ));

    let mut lnk = prologue();
    let at = lnk.offset();
    let mut file = lnk.import(3, "printf").end();
    file.truncate(file.len() - 3);
    cases.push((
        file,
        format!("Truncated IMPORTED_SYMBOL record at 0x{at:X}"),
    ));

    for (file, message) in cases {
        let text = error_text(&file);
        assert!(text.starts_with("PsyQ object parse error: "), "{text}");
        assert!(text.contains(&message), "{text} should contain {message}");
    }
}

#[test]
fn version_signature_and_first_opcode_are_checked() {
    let file = object(Some(MIPS_R3000), &[0; 16]).file;
    assert_eq!(psyq::detect(&file), Some(psyq::Layout::Object));

    let mut version3 = file.clone();
    version3[3] = 3;
    assert_eq!(psyq::detect(&version3), None);
    assert!(!is_claimed(&version3));
    let error = psyq::parse_container(&version3, psyq::Layout::Object).unwrap_err();
    assert_eq!(
        error.to_string(),
        "PsyQ object parse error: Unsupported LNK version 3"
    );

    let mut odd_opcode = file.clone();
    odd_opcode[4] = 3;
    assert_eq!(psyq::detect(&odd_opcode), None);

    let mut signature = file;
    signature[0] = b'l';
    assert_eq!(psyq::detect(&signature), None);
    let error = psyq::parse_container(&signature, psyq::Layout::Object).unwrap_err();
    assert_eq!(
        error.to_string(),
        "PsyQ object parse error: Missing LNK signature"
    );
    let error = psyq::parse_container(b"LN", psyq::Layout::Object).unwrap_err();
    assert_eq!(
        error.to_string(),
        "PsyQ object parse error: Truncated LNK header: 2 B of 4 B"
    );
}

#[test]
fn every_prefix_is_an_error_or_not_claimed() {
    let file = object(Some(MIPS_R3000), &[0x25, 0x08, 0x20, 0x00].repeat(8)).file;
    for end in 0..file.len() {
        let prefix = &file[..end];
        // Up to the header only the bytes `LNK` and the version exist, so
        // nothing is recognized; from the first opcode on, the object is
        // recognized and every prefix lacks its END record.
        if end <= 4 {
            assert!(!is_claimed(prefix), "prefix {end}");
        } else {
            let text = error_text(prefix);
            assert!(
                text.starts_with("PsyQ object parse error"),
                "prefix {end}: {text}"
            );
        }
        assert!(psyq::parse_container(prefix, psyq::Layout::Object).is_err());
    }
}

#[test]
fn byte_mutations_never_panic() {
    let file = object(Some(MIPS_R3000), &[0x25, 0x08, 0x20, 0x00].repeat(8)).file;
    for at in 0..file.len() {
        let original = file[at];
        let mut values = vec![0x00, 0xFF];
        values.extend((0..8).map(|bit| original ^ (1 << bit)));
        for value in values {
            let mut mutated = file.clone();
            mutated[at] = value;
            let _ = psyq::parse_container(&mutated, psyq::Layout::Object);
            let _ = detect_payload(&mutated, &ClassifierOptions::new());
        }
    }
}

#[test]
fn sections_beyond_the_component_limit_are_counted_not_listed() {
    const SECTIONS: u16 = 4097;
    let mut lnk = Lnk::new();
    lnk.processor(MIPS_R3000);
    for id in 1..=SECTIONS {
        lnk.section(id, "d").switch(id);
        lnk.code(&[0xAA]);
    }
    let p = classify(&lnk.end());
    assert_eq!(p.slices.len(), 4096);
    assert!(has_note(
        &p,
        "1 further section with BYTES records not listed (limit 4096)"
    ));
    assert!(has_note(&p, "4097 sections: d (1 B), d (1 B)"));
    assert!(has_note(&p, " and 4089 more"));
}

/// Real objects from IDA's test inputs (`IDA_INPUT_DIR`), read in place:
/// the valid ones classify as PlayStation code, the damaged ones fail with
/// the defect they carry. Skipped without the variable.
#[test]
fn ida_input_objects_parse_or_fail_with_bounded_errors() {
    let Some(dir) = std::env::var_os("IDA_INPUT_DIR").map(PathBuf::from) else {
        eprintln!("skipped: IDA_INPUT_DIR is not set");
        return;
    };
    let valid = [
        "mips_obj1.psx",
        "mips_obj2.psx",
        "mips_cdsfile.psx",
        "mips_gs_135.psx",
        "mips_mcgui.psx",
        "mips_noheap.psx",
        "mips_tuto0.psx",
    ];
    for name in valid {
        let data = std::fs::read(dir.join(name)).expect("IDA input is present");
        let p = classify(&data);
        assert_eq!(p.format.format, FileFormat::PsyqObject, "{name}");
        assert_eq!(
            (p.primary.isa, p.primary.endianness),
            (Isa::Mips, Endianness::Little),
            "{name}"
        );
        let text = p
            .slices
            .iter()
            .find(|s| s.label.as_deref().is_some_and(|l| l.starts_with(".text")))
            .unwrap_or_else(|| panic!("{name}: .text slice"));
        assert_eq!(text.isa, Isa::Mips, "{name}");
    }
    let damaged = [
        ("mips_bad_relocs.psx", "Unknown record opcode 117 at 0x1273"),
        (
            "mips_bad_relocs2.psx",
            "Unexpected 5278 B after the END record at 0x1D9",
        ),
        (
            "mips_bad_symname.psx",
            "Duplicate PROGRAMTYPE record at 0x2B",
        ),
        (
            "mips_huge_bss.psx",
            "Unexpected 4612 B after the END record at 0x473",
        ),
    ];
    for (name, message) in damaged {
        let data = std::fs::read(dir.join(name)).expect("IDA input is present");
        let text = error_text(&data);
        assert!(text.ends_with(message), "{name}: {text}");
    }
}
