use unicode_normalization::UnicodeNormalization;

/// Normalize an email address for use as an identity subject.
/// Trims whitespace, lowercases, and NFC-normalizes.
///
/// We do NOT strip plus-tags or handle domain aliases — that's user policy, not ours.
pub fn normalize(email: &str) -> String {
    email.trim().to_lowercase().nfc().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercases() {
        assert_eq!(normalize("Alice@Example.COM"), "alice@example.com");
    }

    #[test]
    fn trims_whitespace() {
        assert_eq!(normalize("  alice@example.com  "), "alice@example.com");
    }

    #[test]
    fn preserves_plus_tags() {
        assert_eq!(normalize("alice+tag@example.com"), "alice+tag@example.com");
    }

    #[test]
    fn handles_empty() {
        assert_eq!(normalize(""), "");
    }

    #[test]
    fn nfc_normalizes() {
        // e + combining acute (NFD) should round-trip through NFC without error
        let nfd = "caf\u{0065}\u{0301}@example.com"; // café in NFD
        let nfc = "caf\u{00E9}@example.com"; // café in NFC
        assert_eq!(normalize(nfd), normalize(nfc));
    }
}
