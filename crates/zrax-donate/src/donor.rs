//! Donor names, as the server credits them in a post.

use std::fmt;

/// The name the server substitutes when a donor gives none.
pub const ANONYMOUS: &str = "anonymous";

/// Longest donor name the server keeps, in characters.
const MAX_NAME_CHARS: usize = 32;

/// A name the server would replace with [`ANONYMOUS`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Invalid donor name; use letters, digits, '_', '.' and '-' (up to 32 characters)")]
pub struct InvalidDonorName;

/// A donor name the server accepts unchanged: 1 to 32 ASCII letters,
/// digits, `_`, `.` or `-`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DonorName(String);

impl DonorName {
    /// Trim the text and one leading `@`, then apply the server's rule.
    ///
    /// # Errors
    ///
    /// [`InvalidDonorName`] when the server would not keep the name. The
    /// server silently credits such uploads to "anonymous"; a client should
    /// tell the donor instead.
    pub fn parse(raw: &str) -> Result<Self, InvalidDonorName> {
        let name = raw.trim().trim_start_matches('@');
        let is_valid =
            !name.is_empty() && name.len() <= MAX_NAME_CHARS && name.chars().all(is_name_char);
        if is_valid {
            Ok(Self(name.to_string()))
        } else {
            Err(InvalidDonorName)
        }
    }

    /// The name used when the donor gives none.
    pub fn anonymous() -> Self {
        Self(ANONYMOUS.to_string())
    }

    /// The name as sent to the server.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DonorName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_the_server_rule() {
        assert_eq!(
            DonorName::parse("@some_handle").unwrap().as_str(),
            "some_handle"
        );
        assert_eq!(DonorName::parse(" a.b-c_1 ").unwrap().as_str(), "a.b-c_1");
        assert_eq!(DonorName::parse("has space"), Err(InvalidDonorName));
        assert_eq!(DonorName::parse(""), Err(InvalidDonorName));
        assert_eq!(DonorName::parse(&"x".repeat(33)), Err(InvalidDonorName));
        assert_eq!(DonorName::anonymous().as_str(), ANONYMOUS);
    }
}
