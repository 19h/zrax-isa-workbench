//! The XML property list that holds a UDIF image's block tables: a
//! `plist` element whose `dict` maps `resource-fork` to a `dict` that maps
//! `blkx` to an `array` of `dict`s with the keys `Attributes`, `CFName`,
//! `Data` (the block table, base64), `ID` and `Name` (7-Zip
//! `DmgHandler.cpp` `CHandler::Open2`; darling-dmg `src/DMGDisk.cpp`;
//! libdmg-hfsplus `dmg/resources.c`).
//!
//! The reader handles the subset of XML that property lists use: the XML
//! declaration, a `DOCTYPE` without an internal subset, comments, start,
//! end and empty-element tags, and text with the five predefined entities
//! and character references. It walks to the `blkx` array without building
//! a tree; values it does not need are skipped, nesting at most
//! [`MAX_DEPTH`] deep. Every step consumes input, so the walk is bounded by
//! the property list's size.

use super::*;

/// Deepest nesting of `dict` and `array` elements accepted. UDIF property
/// lists nest four deep (`plist` `dict`, `resource-fork` `dict`, `blkx`
/// `array`, entry `dict`).
const MAX_DEPTH: usize = 32;

/// One `blkx` array entry.
#[derive(Debug, Default)]
pub(super) struct Entry {
    /// `CFName`, when present.
    pub(super) cf_name: Option<String>,
    /// `Name`, when present.
    pub(super) name: Option<String>,
    /// `ID`, as stored.
    pub(super) id: Option<String>,
    /// The decoded `Data`: a block table.
    pub(super) data: Option<Vec<u8>>,
}

/// The `blkx` entries of a property list, in array order. A property list
/// without a `resource-fork` `blkx` array has none; only the first of each
/// is read.
pub(super) fn blkx_entries(xml: &[u8]) -> Result<Vec<Entry>> {
    let mut reader = Reader { xml, pos: 0 };
    reader.expect_start("plist")?;
    reader.expect_start("dict")?;
    let mut entries = None;
    reader.each_dict_item(0, |reader, key, token| {
        if key == b"resource-fork" && is_start(&token, "dict") && entries.is_none() {
            entries = Some(reader.resource_fork()?);
            return Ok(());
        }
        reader.skip_value(&token, 1)
    })?;
    reader.expect_end("plist")?;
    Ok(entries.unwrap_or_default())
}

/// A markup or text token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token<'a> {
    /// `<name ...>`
    Start(&'a [u8]),
    /// `<name .../>`
    Empty(&'a [u8]),
    /// `</name>`
    End(&'a [u8]),
    /// Text between tags, as stored.
    Text(&'a [u8]),
    /// The end of the property list.
    Eof,
}

fn is_start(token: &Token<'_>, name: &str) -> bool {
    matches!(token, Token::Start(n) if *n == name.as_bytes())
}

/// The property list being read.
struct Reader<'a> {
    xml: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn fail(&self, what: &str) -> ClassifierError {
        error(format!(
            "Invalid UDIF property list at 0x{:X}: {what}",
            self.pos
        ))
    }

    /// The position of `needle` at or after `from`.
    fn find(&self, from: usize, needle: &[u8]) -> Option<usize> {
        memchr::memmem::find(self.xml.get(from..)?, needle).map(|at| from + at)
    }

    /// Skip markup that carries no data: the XML declaration and other
    /// processing instructions, comments and the `DOCTYPE`.
    fn skip_markup(&mut self) -> Result<bool> {
        let rest = &self.xml[self.pos..];
        let (open, close): (&[u8], &[u8]) = if rest.starts_with(b"<?") {
            (b"<?", b"?>")
        } else if rest.starts_with(b"<!--") {
            (b"<!--", b"-->")
        } else if rest.starts_with(b"<!DOCTYPE") {
            // A DOCTYPE with an internal subset could declare entities;
            // property lists never carry one.
            let end = self
                .find(self.pos, b">")
                .ok_or_else(|| self.fail("unterminated DOCTYPE"))?;
            if self.xml[self.pos..end].contains(&b'[') {
                return Err(self.fail("DOCTYPE internal subsets are not supported"));
            }
            self.pos = end + 1;
            return Ok(true);
        } else if rest.starts_with(b"<!") {
            return Err(self.fail("unsupported markup declaration or CDATA section"));
        } else {
            return Ok(false);
        };
        let end = self
            .find(self.pos + open.len(), close)
            .ok_or_else(|| self.fail("unterminated processing instruction or comment"))?;
        self.pos = end + close.len();
        Ok(true)
    }

    /// The next token.
    fn next(&mut self) -> Result<Token<'a>> {
        loop {
            if self.pos >= self.xml.len() {
                return Ok(Token::Eof);
            }
            if self.xml[self.pos] != b'<' {
                let end = self.find(self.pos, b"<").unwrap_or(self.xml.len());
                let text = &self.xml[self.pos..end];
                self.pos = end;
                return Ok(Token::Text(text));
            }
            if self.skip_markup()? {
                continue;
            }
            let end = self
                .find(self.pos, b">")
                .ok_or_else(|| self.fail("unterminated tag"))?;
            let tag = &self.xml[self.pos + 1..end];
            self.pos = end + 1;
            if let Some(name) = tag.strip_prefix(b"/") {
                return Ok(Token::End(trim_end(name)));
            }
            let (body, empty) = match tag.strip_suffix(b"/") {
                Some(body) => (body, true),
                None => (tag, false),
            };
            let name_end = body
                .iter()
                .position(u8::is_ascii_whitespace)
                .unwrap_or(body.len());
            let name = &body[..name_end];
            if name.is_empty() {
                return Err(self.fail("empty tag name"));
            }
            return Ok(if empty {
                Token::Empty(name)
            } else {
                Token::Start(name)
            });
        }
    }

    /// The next token that is not whitespace between elements; other text
    /// there is an error.
    fn next_markup(&mut self) -> Result<Token<'a>> {
        loop {
            match self.next()? {
                Token::Text(text) if text.iter().all(u8::is_ascii_whitespace) => {}
                Token::Text(_) => return Err(self.fail("unexpected text between elements")),
                token => return Ok(token),
            }
        }
    }

    fn expect_start(&mut self, name: &str) -> Result<()> {
        match self.next_markup()? {
            Token::Start(n) if n == name.as_bytes() => Ok(()),
            _ => Err(self.fail(&format!("expected <{name}>"))),
        }
    }

    fn expect_end(&mut self, name: &str) -> Result<()> {
        match self.next_markup()? {
            Token::End(n) if n == name.as_bytes() => Ok(()),
            _ => Err(self.fail(&format!("expected </{name}>"))),
        }
    }

    /// The text of an element whose start tag was `token`, up to its end
    /// tag; an empty-element tag has none.
    fn text(&mut self, token: &Token<'a>) -> Result<&'a [u8]> {
        let name = match *token {
            Token::Empty(_) => return Ok(b""),
            Token::Start(name) => name,
            _ => return Err(self.fail("expected an element")),
        };
        let text = match self.next()? {
            Token::Text(text) => text,
            Token::End(n) if n == name => return Ok(b""),
            _ => return Err(self.fail("expected text")),
        };
        match self.next()? {
            Token::End(n) if n == name => Ok(text),
            _ => Err(self.fail("expected an end tag after text")),
        }
    }

    /// Skip the value that starts with `token`, nested at `depth`.
    fn skip_value(&mut self, token: &Token<'a>, depth: usize) -> Result<()> {
        match *token {
            Token::Empty(_) => Ok(()),
            Token::Start(b"dict") => self.each_dict_item(depth, |reader, _, token| {
                reader.skip_value(&token, depth + 1)
            }),
            Token::Start(b"array") => {
                self.each_array_item(depth, |reader, token| reader.skip_value(&token, depth + 1))
            }
            Token::Start(_) => self.text(token).map(|_| ()),
            _ => Err(self.fail("expected a value")),
        }
    }

    /// Call `item` with each key and the start token of its value, until
    /// `</dict>`; `item` must consume the value.
    fn each_dict_item(
        &mut self,
        depth: usize,
        mut item: impl FnMut(&mut Self, &[u8], Token<'a>) -> Result<()>,
    ) -> Result<()> {
        if depth >= MAX_DEPTH {
            return Err(self.fail("nesting too deep"));
        }
        loop {
            let token = self.next_markup()?;
            match token {
                Token::End(b"dict") => return Ok(()),
                Token::Start(b"key") | Token::Empty(b"key") => {
                    let key = self.text(&token)?;
                    let value = self.next_markup()?;
                    item(self, key, value)?;
                }
                _ => return Err(self.fail("expected <key> or </dict>")),
            }
        }
    }

    /// Call `item` with the start token of each value until `</array>`;
    /// `item` must consume the value.
    fn each_array_item(
        &mut self,
        depth: usize,
        mut item: impl FnMut(&mut Self, Token<'a>) -> Result<()>,
    ) -> Result<()> {
        if depth >= MAX_DEPTH {
            return Err(self.fail("nesting too deep"));
        }
        loop {
            let token = self.next_markup()?;
            if token == Token::End(b"array") {
                return Ok(());
            }
            item(self, token)?;
        }
    }

    /// The `blkx` array of the `resource-fork` dictionary whose start tag
    /// was just read.
    fn resource_fork(&mut self) -> Result<Vec<Entry>> {
        let mut entries = None;
        self.each_dict_item(1, |reader, key, token| {
            if key == b"blkx" && is_start(&token, "array") && entries.is_none() {
                entries = Some(reader.blkx_array()?);
                return Ok(());
            }
            reader.skip_value(&token, 2)
        })?;
        Ok(entries.unwrap_or_default())
    }

    /// The entries of the `blkx` array whose start tag was just read.
    fn blkx_array(&mut self) -> Result<Vec<Entry>> {
        let mut entries = Vec::new();
        self.each_array_item(2, |reader, token| {
            if entries.len() >= MAX_TABLES {
                return Err(error(format!(
                    "Unsupported UDIF property list: over {MAX_TABLES} block tables"
                )));
            }
            entries.push(reader.entry(&token)?);
            Ok(())
        })?;
        Ok(entries)
    }

    /// One `blkx` array entry: a `dict` whose string and data values are
    /// kept and whose other values are skipped.
    fn entry(&mut self, token: &Token<'a>) -> Result<Entry> {
        let mut entry = Entry::default();
        if !is_start(token, "dict") {
            return Err(self.fail("expected a <dict> block table entry"));
        }
        self.each_dict_item(3, |reader, key, value| {
            let is_string = matches!(value, Token::Start(b"string") | Token::Empty(b"string"));
            let is_data = matches!(value, Token::Start(b"data") | Token::Empty(b"data"));
            match key {
                b"CFName" | b"Name" | b"ID" if is_string => {
                    let text = unescape(reader.text(&value)?)
                        .ok_or_else(|| reader.fail("invalid entity or UTF-8 in a string"))?;
                    match key {
                        b"CFName" => entry.cf_name = Some(text),
                        b"Name" => entry.name = Some(text),
                        _ => entry.id = Some(text),
                    }
                    Ok(())
                }
                b"Data" if is_data => {
                    let text = reader.text(&value)?;
                    entry.data = Some(
                        decode_base64(text)
                            .ok_or_else(|| reader.fail("invalid base64 in a Data value"))?,
                    );
                    Ok(())
                }
                _ => reader.skip_value(&value, 4),
            }
        })?;
        Ok(entry)
    }
}

/// `bytes` without trailing ASCII whitespace (`</key >` is an end tag).
fn trim_end(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(0, |last| last + 1);
    &bytes[..end]
}

/// Text with the predefined entities and character references replaced,
/// or `None` for an unknown entity or text that is not UTF-8.
fn unescape(text: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(text).ok()?;
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let end = rest[at..].find(';')? + at;
        let entity = &rest[at + 1..end];
        let ch = match entity {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let code = if let Some(hex) = entity.strip_prefix("#x") {
                    u32::from_str_radix(hex, 16).ok()?
                } else {
                    entity.strip_prefix('#')?.parse().ok()?
                };
                char::from_u32(code)?
            }
        };
        out.push(ch);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

/// The value of one base64 symbol, or `None`.
fn base64_value(symbol: u8) -> Option<u8> {
    match symbol {
        b'A'..=b'Z' => Some(symbol - b'A'),
        b'a'..=b'z' => Some(symbol - b'a' + 26),
        b'0'..=b'9' => Some(symbol - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode base64 (RFC 4648 section 4, the standard alphabet) with ASCII
/// whitespace anywhere, as property lists wrap it. Padding may only end
/// the text, and the symbols with padding must form whole groups of four.
pub(super) fn decode_base64(text: &[u8]) -> Option<Vec<u8>> {
    let symbols: Vec<u8> = text
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if symbols.len() % 4 != 0 {
        return None;
    }
    let padding = symbols.iter().rev().take_while(|&&b| b == b'=').count();
    if padding > 2 {
        return None;
    }
    let body = &symbols[..symbols.len() - padding];
    let mut out = Vec::with_capacity(body.len() / 4 * 3 + 2);
    let mut group: u32 = 0;
    for (i, &symbol) in body.iter().enumerate() {
        group = group << 6 | u32::from(base64_value(symbol)?);
        if i % 4 == 3 {
            out.extend_from_slice(&group.to_be_bytes()[1..]);
            group = 0;
        }
    }
    // Two trailing symbols carry one byte and four unused bits, three
    // carry two bytes and two unused bits; unused bits must be zero (RFC
    // 4648 section 3.5).
    let (unused_bits, bytes) = match body.len() % 4 {
        0 => return Some(out),
        2 => (4, 1),
        3 => (2, 2),
        _ => return None,
    };
    if group.trailing_zeros() < unused_bits {
        return None;
    }
    let value = (group >> unused_bits).to_be_bytes();
    out.extend_from_slice(&value[4 - bytes..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
	"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>other</key>
	<array><dict><key>x</key><integer>1</integer></dict><true/></array>
	<key>resource-fork</key>
	<dict>
		<key>blkx</key>
		<array>
			<dict>
				<key>Attributes</key>
				<string>0x0050</string>
				<key>CFName</key>
				<string>disk image (Apple_HFS : 4)</string>
				<key>Data</key>
				<data>
				bWlz
				aA==
				</data>
				<key>ID</key>
				<string>4</string>
				<key>Name</key>
				<string> A &amp; B &#x263A;</string>
			</dict>
		</array>
		<key>plst</key>
		<array><dict><key>Data</key><data/></dict></array>
	</dict>
</dict>
</plist>
"#;

    #[test]
    fn blkx_entries_keep_names_ids_and_decoded_data() {
        let entries = blkx_entries(PLIST.as_bytes()).unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.cf_name.as_deref(), Some("disk image (Apple_HFS : 4)"));
        assert_eq!(entry.name.as_deref(), Some(" A & B \u{263A}"));
        assert_eq!(entry.id.as_deref(), Some("4"));
        assert_eq!(entry.data.as_deref(), Some(&b"mish"[..]));
    }

    #[test]
    fn malformed_property_lists_are_errors() {
        for broken in [
            "<dict></dict>",
            "<plist><dict><key>a</key></plist>",
            "<plist><dict>text</dict></plist>",
            "<plist><dict><key>resource-fork</key><dict><key>blkx</key><array><string/>\
             </array></dict></dict></plist>",
            "<!DOCTYPE plist [<!ENTITY a 'b'>]><plist><dict/></plist>",
            "<plist><dict><key>resource-fork</key><dict><key>blkx</key><array><dict>\
             <key>Data</key><data>bWlz=aA==</data></dict></array></dict></dict></plist>",
        ] {
            assert!(blkx_entries(broken.as_bytes()).is_err(), "{broken}");
        }
        for end in 0..PLIST.len() {
            // Every cut either fails or still reads the complete list.
            let _ = blkx_entries(&PLIST.as_bytes()[..end]);
        }
    }

    #[test]
    fn nesting_is_bounded() {
        let deep = format!(
            "<plist><dict><key>a</key>{}{}</dict></plist>",
            "<array>".repeat(100),
            "</array>".repeat(100)
        );
        let message = blkx_entries(deep.as_bytes()).unwrap_err().to_string();
        assert!(message.contains("nesting too deep"), "{message}");
    }

    #[test]
    fn base64_decodes_padded_and_wrapped_text() {
        assert_eq!(decode_base64(b"bWlzaA==").unwrap(), b"mish");
        assert_eq!(decode_base64(b"bWlz\n\taGU=").unwrap(), b"mishe");
        assert_eq!(decode_base64(b"").unwrap(), b"");
        assert!(decode_base64(b"bWlza").is_none());
        assert!(decode_base64(b"bW=z").is_none());
        assert!(
            decode_base64(b"bWlzaB==").is_none(),
            "unused bits must be zero"
        );
        assert!(decode_base64(b"bWl*").is_none());
    }

    #[test]
    fn entities_are_replaced_and_unknown_ones_rejected() {
        assert_eq!(unescape(b"a &lt;b&gt; &#65;").unwrap(), "a <b> A");
        assert!(unescape(b"&nope;").is_none());
        assert!(unescape(b"&amp").is_none());
    }
}
