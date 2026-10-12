//! A bounded XML reader for ODX documents (XML 1.0, fifth edition, as far
//! as ODX uses it): elements, attributes, character data, CDATA sections,
//! the five predefined entities and character references. Comments,
//! processing instructions and the document type declaration are skipped;
//! no entity is ever expanded from a DTD, so entity-expansion attacks have
//! nothing to work with. Parsing is iterative with a depth limit.

use super::*;

/// Nesting deeper than this is not an ODX document.
const MAX_DEPTH: usize = 256;

/// One element. Children are indices into [`Document::nodes`].
#[derive(Debug)]
pub(super) struct Element {
    pub name: String,
    pub attributes: Vec<(String, String)>,
    /// Character data directly inside the element, entities decoded.
    pub text: String,
    /// File range of the first run of character data, for stored offsets.
    pub text_span: Option<(usize, usize)>,
    pub children: Vec<usize>,
}

impl Element {
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(n, _)| n == name || n.rsplit(':').next() == Some(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A parsed document; node 0 is the root element.
#[derive(Debug)]
pub(super) struct Document {
    pub nodes: Vec<Element>,
}

impl Document {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data))
            .map_err(|e| error(format!("Invalid UTF-8 in XML at 0x{:X}", e.valid_up_to())))?;
        let base = data.len() - text.len();
        let mut parser = Parser {
            text,
            base,
            pos: 0,
            nodes: Vec::new(),
            stack: Vec::new(),
        };
        parser.run()?;
        if parser.nodes.is_empty() {
            return Err(error("Missing XML root element"));
        }
        Ok(Self {
            nodes: parser.nodes,
        })
    }

    pub fn root(&self) -> &Element {
        &self.nodes[0]
    }

    /// The first child of `parent` named `name`.
    pub fn child(&self, parent: usize, name: &str) -> Option<usize> {
        self.nodes[parent]
            .children
            .iter()
            .copied()
            .find(|&i| self.nodes[i].name == name)
    }

    /// Text of the child of `parent` named `name`, trimmed.
    pub fn child_text(&self, parent: usize, name: &str) -> Option<&str> {
        self.child(parent, name).map(|i| self.nodes[i].text.trim())
    }

    /// Every element named `name` under `parent`, in document order.
    pub fn descendants(&self, parent: usize, name: &str) -> Vec<usize> {
        let mut found = Vec::new();
        let mut pending = vec![parent];
        while let Some(node) = pending.pop() {
            for &child in self.nodes[node].children.iter().rev() {
                pending.push(child);
            }
            if node != parent && self.nodes[node].name == name {
                found.push(node);
            }
        }
        found.sort_unstable();
        found
    }
}

struct Parser<'a> {
    text: &'a str,
    base: usize,
    pos: usize,
    nodes: Vec<Element>,
    stack: Vec<usize>,
}

impl Parser<'_> {
    fn rest(&self) -> &str {
        &self.text[self.pos..]
    }

    fn offset(&self) -> usize {
        self.base + self.pos
    }

    /// Skip past `end`, which must occur.
    fn skip_past(&mut self, end: &str, what: &str) -> Result<()> {
        let at = self
            .rest()
            .find(end)
            .ok_or_else(|| error(format!("Unterminated XML {what} at 0x{:X}", self.offset())))?;
        self.pos += at + end.len();
        Ok(())
    }

    fn run(&mut self) -> Result<()> {
        while self.pos < self.text.len() {
            let rest = self.rest();
            if rest.starts_with("<?") {
                self.skip_past("?>", "processing instruction")?;
            } else if rest.starts_with("<!--") {
                self.skip_past("-->", "comment")?;
            } else if rest.starts_with("<![CDATA[") {
                let start = self.pos + 9;
                self.skip_past("]]>", "CDATA section")?;
                let content = &self.text[start..self.pos - 3];
                self.character_data(content, start, false)?;
            } else if rest.starts_with("<!") {
                // A document type declaration; its entities are never used.
                self.skip_doctype()?;
            } else if rest.starts_with("</") {
                self.end_tag()?;
            } else if rest.starts_with('<') {
                self.start_tag()?;
            } else {
                let len = rest.find('<').unwrap_or(rest.len());
                let start = self.pos;
                self.pos += len;
                let content = &self.text[start..self.pos];
                self.character_data(content, start, true)?;
            }
        }
        if !self.stack.is_empty() {
            return Err(error("Truncated XML document: unclosed elements"));
        }
        Ok(())
    }

    fn skip_doctype(&mut self) -> Result<()> {
        // Internal subsets end at "]>"; external ones at the first '>'.
        let rest = self.rest();
        let end = match (rest.find('['), rest.find('>')) {
            (Some(open), Some(close)) if open < close => rest.find("]>").map(|i| i + 2),
            (_, Some(close)) => Some(close + 1),
            _ => None,
        };
        let end = end.ok_or_else(|| error("Unterminated XML document type declaration"))?;
        self.pos += end;
        Ok(())
    }

    fn character_data(&mut self, content: &str, start: usize, decode: bool) -> Result<()> {
        let Some(&current) = self.stack.last() else {
            if content.trim().is_empty() {
                return Ok(());
            }
            return Err(error(format!(
                "Invalid character data outside the XML root at 0x{:X}",
                self.base + start
            )));
        };
        let decoded = if decode {
            decode_entities(content)?
        } else {
            content.to_string()
        };
        let node = &mut self.nodes[current];
        if node.text_span.is_none() && !content.trim().is_empty() {
            node.text_span = Some((self.base + start, self.base + start + content.len()));
        }
        node.text.push_str(&decoded);
        Ok(())
    }

    fn start_tag(&mut self) -> Result<()> {
        let tag_start = self.offset();
        let end = self
            .rest()
            .find('>')
            .ok_or_else(|| error(format!("Unterminated XML tag at 0x{tag_start:X}")))?;
        let inner = &self.text[self.pos + 1..self.pos + end];
        self.pos += end + 1;
        let (inner, empty) = match inner.strip_suffix('/') {
            Some(inner) => (inner, true),
            None => (inner, false),
        };
        let (name, attributes) = parse_tag(inner, tag_start)?;
        if self.stack.is_empty() && !self.nodes.is_empty() {
            return Err(error("Invalid XML: more than one root element"));
        }
        if self.stack.len() >= MAX_DEPTH {
            return Err(error("XML nesting exceeds 256 levels"));
        }
        let index = self.nodes.len();
        if let Some(&parent) = self.stack.last() {
            self.nodes[parent].children.push(index);
        }
        self.nodes.push(Element {
            name,
            attributes,
            text: String::new(),
            text_span: None,
            children: Vec::new(),
        });
        if !empty {
            self.stack.push(index);
        }
        Ok(())
    }

    fn end_tag(&mut self) -> Result<()> {
        let at = self.offset();
        let end = self
            .rest()
            .find('>')
            .ok_or_else(|| error(format!("Unterminated XML end tag at 0x{at:X}")))?;
        let name = self.text[self.pos + 2..self.pos + end].trim();
        self.pos += end + 1;
        let open = self
            .stack
            .pop()
            .ok_or_else(|| error(format!("Unbalanced XML end tag at 0x{at:X}")))?;
        if self.nodes[open].name != name {
            return Err(error(format!(
                "Mismatched XML end tag {name} for {} at 0x{at:X}",
                self.nodes[open].name
            )));
        }
        Ok(())
    }
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | ':' | '-' | '.')
}

/// Element name and attributes of a start tag's inside.
fn parse_tag(inner: &str, at: usize) -> Result<(String, Vec<(String, String)>)> {
    let invalid = || error(format!("Invalid XML tag at 0x{at:X}"));
    let name_len = inner
        .find(|c: char| !is_name_char(c))
        .unwrap_or(inner.len());
    if name_len == 0 {
        return Err(invalid());
    }
    let name = inner[..name_len].to_string();
    let mut rest = inner[name_len..].trim_start();
    let mut attributes = Vec::new();
    while !rest.is_empty() {
        let key_len = rest.find(|c: char| !is_name_char(c)).unwrap_or(rest.len());
        if key_len == 0 {
            return Err(invalid());
        }
        let key = rest[..key_len].to_string();
        rest = rest[key_len..].trim_start();
        rest = rest.strip_prefix('=').ok_or_else(invalid)?.trim_start();
        let quote = rest
            .chars()
            .next()
            .filter(|c| matches!(c, '"' | '\''))
            .ok_or_else(invalid)?;
        let value_end = rest[1..].find(quote).ok_or_else(invalid)?;
        attributes.push((key, decode_entities(&rest[1..=value_end])?));
        rest = rest[value_end + 2..].trim_start();
    }
    Ok((name, attributes))
}

/// Decode the predefined entities and character references.
fn decode_entities(text: &str) -> Result<String> {
    if !text.contains('&') {
        return Ok(text.to_string());
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        let semi = after
            .find(';')
            .filter(|&i| i <= 10)
            .ok_or_else(|| error("Invalid XML entity reference"))?;
        let entity = &after[..semi];
        let decoded = match entity {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let code = if let Some(hex) = entity.strip_prefix("#x") {
                    u32::from_str_radix(hex, 16).ok()
                } else if let Some(decimal) = entity.strip_prefix('#') {
                    decimal.parse().ok()
                } else {
                    None
                };
                code.and_then(char::from_u32)
                    .ok_or_else(|| error(format!("Unsupported XML entity &{entity};")))?
            }
        };
        out.push(decoded);
        rest = &after[semi + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documents_parse_into_elements_attributes_and_text() {
        let doc = Document::parse(
            b"<?xml version=\"1.0\"?><!-- c --><A x='1'><B>t &amp; u</B><C/><![CDATA[<raw>]]></A>",
        )
        .unwrap();
        assert_eq!(doc.root().name, "A");
        assert_eq!(doc.root().attribute("x"), Some("1"));
        assert_eq!(doc.child_text(0, "B"), Some("t & u"));
        assert_eq!(doc.root().text, "<raw>");
        assert_eq!(doc.descendants(0, "C").len(), 1);
    }

    #[test]
    fn malformed_documents_are_errors() {
        for bad in [
            &b"<A><B></A>"[..],
            b"<A>",
            b"<A></A><B/>",
            b"<A>&bogus;</A>",
            b"<A x=1/>",
            b"text<A/>",
        ] {
            assert!(
                Document::parse(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn doctype_entities_are_never_expanded() {
        let doc = Document::parse(b"<!DOCTYPE A [<!ENTITY e \"xxxxxxxx\">]><A>plain</A>").unwrap();
        assert_eq!(doc.root().text, "plain");
        assert!(Document::parse(b"<!DOCTYPE A [<!ENTITY e \"x\">]><A>&e;</A>").is_err());
    }
}
