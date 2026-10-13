//! The fixed, variable and auxiliary headers: `include/nlm/internal.h`,
//! `external.h` and the target `*-ext.h` files for the layouts, and
//! `bfd/nlmcode.h` (`nlm_swap_variable_header_in`,
//! `nlm_swap_auxiliary_headers_in`) for how they are read.

use super::*;

/// `NLM_MODULE_NAME_SIZE`: the module name field, length byte and NUL
/// included.
const NLM_MODULE_NAME_SIZE: usize = 14;
/// Longest module name: a DOS 8.3 name, as `nlmconv` caps it
/// (`NLM_MODULE_NAME_SIZE - 2`).
const MAX_MODULE_NAME_LENGTH: u8 = 12;
/// Words of the fixed header after the module name, `codeImageOffset` to
/// `flags`.
const FIXED_HEADER_WORDS: usize = 22;

/// `NLM_MAX_DESCRIPTION_LENGTH`.
const NLM_MAX_DESCRIPTION_LENGTH: u8 = 127;
/// `NLM_MAX_SCREEN_NAME_LENGTH`.
const NLM_MAX_SCREEN_NAME_LENGTH: u8 = 71;
/// `NLM_MAX_THREAD_NAME_LENGTH`.
const NLM_MAX_THREAD_NAME_LENGTH: u8 = 71;
/// `NLM_OLD_THREAD_NAME_LENGTH`: the unused `" LONG"` field.
const NLM_OLD_THREAD_NAME_LENGTH: usize = 5;

/// `CyGnUsEx`: the data stamp of the custom header that locates the
/// original object file's section table.
const CYGNUS_STAMP: &[u8] = b"CyGnUsEx";
/// Size of a custom header's `dataStamp`.
const DATA_STAMP_SIZE: usize = 8;

/// Words of a `VeRsIoN#` header after its stamp.
const VERSION_WORDS: usize = 6;
/// Words of a `MeSsAgEs` header after its stamp.
const EXTENDED_WORDS: usize = 29;
/// `MeSsAgEs` words between the shared data image and `productID`: the
/// shared fixup, import, export and debug tables and the shared
/// initialization and exit procedures.
const EXTENDED_SHARED_TABLE_WORDS: usize = 10;
/// `reserved0` to `reserved5` at the end of a `MeSsAgEs` header.
const EXTENDED_RESERVED_WORDS: usize = 6;

/// Most auxiliary headers read (our bound; `nlmconv` writes at most five).
const MAX_AUXILIARY_HEADERS: usize = 64;

/// The fixed header.
pub(super) struct FixedHeader<'a> {
    /// Header version.
    pub(super) version: u32,
    /// The 14-byte `moduleName` field.
    name_field: &'a [u8],
    /// `codeImageOffset` and `codeImageSize`.
    pub(super) code_image: Extent,
    /// `dataImageOffset` and `dataImageSize`.
    pub(super) data_image: Extent,
    /// Bytes allocated after the data image at load time; not stored.
    pub(super) uninitialized_data_size: u32,
    /// `customDataOffset` and `customDataSize`.
    pub(super) custom_data: Extent,
    /// Module dependency list.
    pub(super) module_dependencies: Table,
    /// Relocation fixups.
    pub(super) relocation_fixups: Table,
    /// Import records.
    pub(super) external_references: Table,
    /// Export records.
    pub(super) publics: Table,
    /// Debug records.
    pub(super) debug_records: Table,
    /// Start procedure, as a code image offset.
    pub(super) code_start: u32,
    /// Exit procedure, as a code image offset.
    pub(super) exit_procedure: u32,
    /// Check-unload procedure, as a code image offset (0: none).
    pub(super) check_unload_procedure: u32,
    /// `TYPE` keyword value.
    pub(super) module_type: u32,
    /// `flags` word.
    pub(super) flags: u32,
    /// File offset just past the fixed header.
    pub(super) end: usize,
}

impl<'a> FixedHeader<'a> {
    /// The fixed header at `start`, whose signature the caller checked:
    /// version, module name, the backend's padding, then 22 words.
    pub(super) fn parse(reader: Reader<'a>, start: usize, backend: &Backend) -> Result<Self> {
        let size = SIGNATURE_SIZE
            + WORD_SIZE
            + NLM_MODULE_NAME_SIZE
            + backend.name_padding
            + FIXED_HEADER_WORDS * WORD_SIZE;
        reader.bytes(start, size, "fixed header")?;
        let mut cursor = Cursor::new(reader, start + SIGNATURE_SIZE);
        let version = cursor.word("header version")?;
        let name_field = cursor.bytes(NLM_MODULE_NAME_SIZE, "module name")?;
        cursor.bytes(backend.name_padding, "fixed header padding")?;
        // The remaining fields, in wire order.
        let code_image = cursor.extent("code image")?;
        let data_image = cursor.extent("data image")?;
        let uninitialized_data_size = cursor.word("uninitialized data size")?;
        let custom_data = cursor.extent("custom data")?;
        let module_dependencies = cursor.table("module dependencies")?;
        let relocation_fixups = cursor.table("relocation fixups")?;
        let external_references = cursor.table("external references")?;
        let publics = cursor.table("publics")?;
        let debug_records = cursor.table("debug records")?;
        let code_start = cursor.word("code start offset")?;
        let exit_procedure = cursor.word("exit procedure offset")?;
        let check_unload_procedure = cursor.word("check-unload procedure offset")?;
        let module_type = cursor.word("module type")?;
        let flags = cursor.word("flags")?;
        Ok(Self {
            version,
            name_field,
            code_image,
            data_image,
            uninitialized_data_size,
            custom_data,
            module_dependencies,
            relocation_fixups,
            external_references,
            publics,
            debug_records,
            code_start,
            exit_procedure,
            check_unload_procedure,
            module_type,
            flags,
            end: cursor.pos,
        })
    }

    /// The module name: a length byte of 1 to 12, then the name.
    pub(super) fn module_name(&self) -> Result<&'a [u8]> {
        let len = self.name_field[0];
        if len == 0 || len > MAX_MODULE_NAME_LENGTH {
            return Err(error(format!(
                "Invalid module name length {len} (1 to {MAX_MODULE_NAME_LENGTH} B)"
            )));
        }
        // The field holds 14 bytes, so a length of at most 12 fits.
        Ok(&self.name_field[1..=usize::from(len)])
    }
}

/// The variable header: description, stack size, the reserved word, the
/// old thread name, screen name and thread name, all present and in this
/// order.
pub(super) struct VariableHeader<'a> {
    /// `descriptionText` without its NUL.
    pub(super) description: &'a [u8],
    /// Stack size in bytes.
    pub(super) stack_size: u32,
    /// `screenName` without its NUL.
    pub(super) screen_name: &'a [u8],
    /// `threadName` without its NUL.
    pub(super) thread_name: &'a [u8],
    /// File offset just past the variable header.
    pub(super) end: usize,
}

impl<'a> VariableHeader<'a> {
    /// The variable header at `start`, right after the fixed header.
    pub(super) fn parse(reader: Reader<'a>, start: usize) -> Result<Self> {
        let mut cursor = Cursor::new(reader, start);
        let description = terminated_text(&mut cursor, "description", NLM_MAX_DESCRIPTION_LENGTH)?;
        let stack_size = cursor.word("stack size")?;
        cursor.word("reserved word")?;
        cursor.bytes(NLM_OLD_THREAD_NAME_LENGTH, "old thread name")?;
        let screen_name = terminated_text(&mut cursor, "screen name", NLM_MAX_SCREEN_NAME_LENGTH)?;
        let thread_name = terminated_text(&mut cursor, "thread name", NLM_MAX_THREAD_NAME_LENGTH)?;
        Ok(Self {
            description,
            stack_size,
            screen_name,
            thread_name,
            end: cursor.pos,
        })
    }
}

/// A length byte of at most `max`, the text, and its NUL terminator. The
/// terminator is read but not checked, as binutils reads it.
fn terminated_text<'a>(cursor: &mut Cursor<'a>, what: &str, max: u8) -> Result<&'a [u8]> {
    let at = cursor.pos;
    let len = cursor.byte(what)?;
    if len > max {
        return Err(error(format!(
            "Invalid {what} length {len} at 0x{at:X} (at most {max})"
        )));
    }
    let text = cursor.bytes(usize::from(len), what)?;
    cursor.bytes(1, what)?;
    Ok(text)
}

/// The auxiliary header stamps `nlm_swap_auxiliary_headers_in` knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stamp {
    /// `VeRsIoN#`: module version and date.
    Version,
    /// `CoPyRiGhT=`: copyright message.
    Copyright,
    /// `MeSsAgEs`: the extended header.
    Extended,
    /// `CuStHeAd`: a custom header.
    Custom,
}

impl Stamp {
    const ALL: [Self; 4] = [Self::Version, Self::Copyright, Self::Extended, Self::Custom];

    fn name(self) -> &'static str {
        match self {
            Self::Version => "VeRsIoN#",
            Self::Copyright => "CoPyRiGhT=",
            Self::Extended => "MeSsAgEs",
            Self::Custom => "CuStHeAd",
        }
    }

    /// The stamp at `pos`, if any. Auxiliary headers end at the first
    /// position without one ("There is no way to identify the end of the
    /// auxiliary headers except by finding a header without a recognized
    /// 'stamp'").
    fn at(data: &[u8], pos: usize) -> Option<Self> {
        let rest = data.get(pos..)?;
        Self::ALL
            .into_iter()
            .find(|stamp| rest.starts_with(stamp.name().as_bytes()))
    }
}

/// A `VeRsIoN#` header.
pub(super) struct VersionHeader {
    major: u32,
    minor: u32,
    revision: u32,
    year: u32,
    month: u32,
    day: u32,
}

impl VersionHeader {
    fn parse(cursor: &mut Cursor<'_>) -> Result<Self> {
        let what = "VeRsIoN# header";
        cursor
            .reader
            .bytes(cursor.pos, VERSION_WORDS * WORD_SIZE, what)?;
        let major = cursor.word(what)?;
        let minor = cursor.word(what)?;
        let revision = cursor.word(what)?;
        let year = cursor.word(what)?;
        let month = cursor.word(what)?;
        let day = cursor.word(what)?;
        Ok(Self {
            major,
            minor,
            revision,
            year,
            month,
            day,
        })
    }

    /// `"version 6.0, revision 5, dated 2002-04-22"`.
    pub(super) fn describe(&self) -> String {
        let date = if (1..=12).contains(&self.month) && (1..=31).contains(&self.day) {
            format!("dated {}-{:02}-{:02}", self.year, self.month, self.day)
        } else {
            format!(
                "date fields {}/{}/{} are not a calendar date",
                self.year, self.month, self.day
            )
        };
        format!(
            "version {}.{}, revision {}, {date}",
            self.major, self.minor, self.revision
        )
    }
}

/// The fields of a `MeSsAgEs` header that name stored data or identify the
/// module.
pub(super) struct ExtendedHeader {
    /// Language of the message file.
    pub(super) language_id: u32,
    /// Message file.
    pub(super) message_file: Extent,
    /// Messages in the message file.
    pub(super) message_count: u32,
    /// Help file.
    pub(super) help_file: Extent,
    /// RPC description data (`XDCDATA`).
    pub(super) rpc_data: Extent,
    /// Code image of an included shared library.
    pub(super) shared_code: Extent,
    /// Data image of an included shared library.
    pub(super) shared_data: Extent,
    /// `productID`.
    pub(super) product_id: u32,
}

impl ExtendedHeader {
    fn parse(cursor: &mut Cursor<'_>) -> Result<Self> {
        let what = "MeSsAgEs header";
        cursor
            .reader
            .bytes(cursor.pos, EXTENDED_WORDS * WORD_SIZE, what)?;
        let language_id = cursor.word(what)?;
        let message_file = cursor.extent(what)?;
        let message_count = cursor.word(what)?;
        let help_file = cursor.extent(what)?;
        let rpc_data = cursor.extent(what)?;
        let shared_code = cursor.extent(what)?;
        let shared_data = cursor.extent(what)?;
        cursor.bytes(EXTENDED_SHARED_TABLE_WORDS * WORD_SIZE, what)?;
        let product_id = cursor.word(what)?;
        cursor.bytes(EXTENDED_RESERVED_WORDS * WORD_SIZE, what)?;
        Ok(Self {
            language_id,
            message_file,
            message_count,
            help_file,
            rpc_data,
            shared_code,
            shared_data,
            product_id,
        })
    }
}

/// A `CuStHeAd` header.
pub(super) struct CustomHeader<'a> {
    /// File offset of the header's stamp.
    pub(super) offset: usize,
    /// `dataOffset` and `dataLength`; 0 when the header is too short to
    /// hold them.
    pub(super) data: Extent,
    /// `dataStamp`; empty when the header is too short to hold one.
    pub(super) data_stamp: &'a [u8],
}

impl<'a> CustomHeader<'a> {
    /// The fields after the stamp, read as binutils reads them: the
    /// `length` word counts the bytes after it, and `dataOffset`,
    /// `dataLength` and `dataStamp` are present only when it covers them.
    /// A length between two words and two words plus the stamp skips
    /// nothing beyond the two words, as in binutils.
    fn parse(cursor: &mut Cursor<'a>, offset: usize) -> Result<Self> {
        let what = "CuStHeAd header";
        let length = to_usize(cursor.word(what)?);
        let data_offset = if length >= WORD_SIZE {
            cursor.word(what)?
        } else {
            0
        };
        let data_size = if length >= 2 * WORD_SIZE {
            cursor.word(what)?
        } else {
            0
        };
        let stamped_length = 2 * WORD_SIZE + DATA_STAMP_SIZE;
        let data_stamp = if length >= stamped_length {
            cursor.bytes(DATA_STAMP_SIZE, what)?
        } else {
            &[]
        };
        if length > stamped_length {
            cursor.bytes(length - stamped_length, what)?;
        }
        Ok(Self {
            offset,
            data: Extent {
                offset: data_offset,
                size: data_size,
            },
            data_stamp,
        })
    }

    /// Whether the data is the Cygnus section table.
    pub(super) fn is_cygnus(&self) -> bool {
        self.data_stamp == CYGNUS_STAMP
    }
}

/// The auxiliary headers after the variable header.
#[derive(Default)]
pub(super) struct AuxiliaryHeaders<'a> {
    /// `VeRsIoN#`.
    pub(super) version: Option<VersionHeader>,
    /// `CoPyRiGhT=` message without its NUL.
    pub(super) copyright: Option<&'a [u8]>,
    /// `MeSsAgEs`.
    pub(super) extended: Option<ExtendedHeader>,
    /// `CuStHeAd` headers, in file order.
    pub(super) custom: Vec<CustomHeader<'a>>,
    /// File offset just past the last auxiliary header.
    pub(super) end: usize,
}

impl<'a> AuxiliaryHeaders<'a> {
    /// The auxiliary headers from `start` up to the first position without
    /// a known stamp. A module carries at most one version, copyright and
    /// extended header.
    pub(super) fn parse(reader: Reader<'a>, start: usize) -> Result<Self> {
        let mut headers = Self::default();
        let mut cursor = Cursor::new(reader, start);
        let mut read = 0;
        while let Some(stamp) = Stamp::at(reader.data, cursor.pos) {
            if read == MAX_AUXILIARY_HEADERS {
                return Err(error(format!(
                    "Invalid auxiliary headers: more than {MAX_AUXILIARY_HEADERS} before 0x{:X}",
                    cursor.pos
                )));
            }
            read += 1;
            headers.read(stamp, &mut cursor)?;
        }
        headers.end = cursor.pos;
        Ok(headers)
    }

    /// The header whose stamp is at the cursor.
    fn read(&mut self, stamp: Stamp, cursor: &mut Cursor<'a>) -> Result<()> {
        let at = cursor.pos;
        let duplicate = match stamp {
            Stamp::Version => self.version.is_some(),
            Stamp::Copyright => self.copyright.is_some(),
            Stamp::Extended => self.extended.is_some(),
            Stamp::Custom => false,
        };
        if duplicate {
            return Err(error(format!(
                "Duplicate {} header at 0x{at:X}",
                stamp.name()
            )));
        }
        cursor.bytes(stamp.name().len(), stamp.name())?;
        match stamp {
            Stamp::Version => self.version = Some(VersionHeader::parse(cursor)?),
            Stamp::Copyright => {
                self.copyright = Some(terminated_text(cursor, "copyright message", u8::MAX)?);
            }
            Stamp::Extended => self.extended = Some(ExtendedHeader::parse(cursor)?),
            Stamp::Custom => self.custom.push(CustomHeader::parse(cursor, at)?),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A little-endian reader over `data`.
    fn le(data: &[u8]) -> Reader<'_> {
        Reader::new(data, false)
    }

    #[test]
    fn module_names_are_counted_dos_names() {
        let mut field = [0u8; NLM_MODULE_NAME_SIZE];
        field[0] = 11;
        field[1..12].copy_from_slice(b"IPTRACE.NLM");
        let data = fixed_header_bytes(&field);
        let header = FixedHeader::parse(le(&data), 0, Layout::I386.backend()).unwrap();
        assert_eq!(header.module_name().unwrap(), b"IPTRACE.NLM");
        for len in [0, 13, 255] {
            field[0] = len;
            let data = fixed_header_bytes(&field);
            let header = FixedHeader::parse(le(&data), 0, Layout::I386.backend()).unwrap();
            assert_eq!(
                header.module_name().unwrap_err().to_string(),
                format!("NetWare module parse error: Invalid module name length {len} (1 to 12 B)")
            );
        }
    }

    /// An i386 fixed header with `name` and every word 0.
    fn fixed_header_bytes(name: &[u8; NLM_MODULE_NAME_SIZE]) -> Vec<u8> {
        let mut data = I386_SIGNATURE.to_vec();
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(name);
        data.extend_from_slice(&[0; FIXED_HEADER_WORDS * WORD_SIZE]);
        data
    }

    #[test]
    fn fixed_header_size_depends_on_the_padding() {
        let data = fixed_header_bytes(&[0; NLM_MODULE_NAME_SIZE]);
        assert_eq!(data.len(), 130);
        let header = FixedHeader::parse(le(&data), 0, Layout::I386.backend()).unwrap();
        assert_eq!(header.end, 130);
        assert_eq!(
            FixedHeader::parse(le(&data), 0, Layout::Sparc.backend())
                .err()
                .unwrap()
                .to_string(),
            "NetWare module parse error: Truncated fixed header at 0x0 + 132 B"
        );
    }

    #[test]
    fn text_lengths_are_limited_and_terminated() {
        let data = [3, b'a', b'b', b'c', 0, 200, 0];
        let mut cursor = Cursor::new(le(&data), 0);
        assert_eq!(
            terminated_text(&mut cursor, "description", 127).unwrap(),
            b"abc"
        );
        assert_eq!(cursor.pos, 5);
        assert_eq!(
            terminated_text(&mut cursor, "description", 127)
                .unwrap_err()
                .to_string(),
            "NetWare module parse error: Invalid description length 200 at 0x5 (at most 127)"
        );
        let mut cursor = Cursor::new(le(&data[..4]), 0);
        assert!(terminated_text(&mut cursor, "description", 127).is_err());
    }

    #[test]
    fn auxiliary_headers_end_at_an_unknown_stamp() {
        let mut data = b"VeRsIoN#".to_vec();
        for word in [6u32, 0, 5, 2002, 4, 22] {
            data.extend_from_slice(&word.to_le_bytes());
        }
        data.extend_from_slice(b"CoPyRiGhT=\x02(c)\0");
        data.extend_from_slice(b"\0\0\0\0padding");
        let headers = AuxiliaryHeaders::parse(le(&data), 0).unwrap();
        assert_eq!(
            headers.version.unwrap().describe(),
            "version 6.0, revision 5, dated 2002-04-22"
        );
        assert_eq!(headers.copyright, Some(b"(c" as &[u8]));
        assert_eq!(headers.end, 32 + 14);

        let mut twice = data[..32].to_vec();
        twice.extend_from_slice(&data[..32]);
        assert_eq!(
            AuxiliaryHeaders::parse(le(&twice), 0)
                .err()
                .unwrap()
                .to_string(),
            "NetWare module parse error: Duplicate VeRsIoN# header at 0x20"
        );
    }

    #[test]
    fn custom_headers_read_only_the_fields_their_length_covers() {
        let mut data = b"CuStHeAd".to_vec();
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&0x100u32.to_le_bytes());
        data.extend_from_slice(b"CuStHeAd");
        data.extend_from_slice(&20u32.to_le_bytes());
        data.extend_from_slice(&0x200u32.to_le_bytes());
        data.extend_from_slice(&0x10u32.to_le_bytes());
        data.extend_from_slice(b"CyGnUsEx");
        data.extend_from_slice(b"more");
        let headers = AuxiliaryHeaders::parse(le(&data), 0).unwrap();
        assert_eq!(headers.custom.len(), 2);
        assert_eq!(
            headers.custom[0].data,
            Extent {
                offset: 0x100,
                size: 0
            }
        );
        assert!(!headers.custom[0].is_cygnus());
        assert_eq!(headers.custom[1].offset, 16);
        assert!(headers.custom[1].is_cygnus());
        assert_eq!(headers.end, data.len());
    }

    #[test]
    fn auxiliary_headers_are_bounded() {
        let mut data = Vec::new();
        for _ in 0..=MAX_AUXILIARY_HEADERS {
            data.extend_from_slice(b"CuStHeAd");
            data.extend_from_slice(&0u32.to_le_bytes());
        }
        assert_eq!(
            AuxiliaryHeaders::parse(le(&data), 0)
                .err()
                .unwrap()
                .to_string(),
            "NetWare module parse error: Invalid auxiliary headers: more than 64 before 0x300"
        );
    }
}
