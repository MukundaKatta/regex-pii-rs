//! # regex-pii-rs
//!
//! Detect and redact common PII (emails, NA-format phones, US SSNs,
//! credit-card-shaped numbers, prefixed API keys) without pulling in
//! the `regex` crate. Hand-rolled scanners, zero deps.
//!
//! ## Example
//!
//! ```
//! use regex_pii_rs::{find, redact};
//! let s = "Contact jane.doe@example.com or 555-123-4567.";
//! let hits = find(s);
//! assert!(hits.iter().any(|f| f.kind == "email"));
//! assert!(!redact(s).contains("jane.doe"));
//! ```

#![deny(missing_docs)]

/// One detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Category: `email`, `phone`, `ssn`, `credit_card`, `api_key`.
    pub kind: &'static str,
    /// Matched text.
    pub value: String,
    /// Byte offset in the input.
    pub byte_pos: usize,
}

/// Return every detection in `s`, sorted by position.
///
/// Overlapping detections are resolved in favor of the one that starts
/// earliest, and—on ties—the longer one. This prevents a digit run
/// embedded in a wider match (e.g. the trailing digits of an API key, or
/// a phone-shaped sequence inside a credit-card span) from being reported
/// as a second, spurious finding.
pub fn find(s: &str) -> Vec<Finding> {
    let mut all = Vec::new();
    all.extend(scan_emails(s));
    all.extend(scan_phones(s));
    all.extend(scan_ssns(s));
    all.extend(scan_cards(s));
    all.extend(scan_api_keys(s));
    // Sort by start position, then by descending length so the widest
    // match at a given offset is considered first.
    all.sort_by(|a, b| {
        a.byte_pos
            .cmp(&b.byte_pos)
            .then_with(|| b.value.len().cmp(&a.value.len()))
    });

    let mut out: Vec<Finding> = Vec::with_capacity(all.len());
    let mut cursor = 0;
    for f in all {
        if f.byte_pos < cursor {
            continue; // contained in / overlapping a kept finding
        }
        cursor = f.byte_pos + f.value.len();
        out.push(f);
    }
    out
}

/// Replace every finding with `[REDACTED:<kind>]`.
pub fn redact(s: &str) -> String {
    let findings = find(s);
    if findings.is_empty() {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut cursor = 0;
    for f in &findings {
        // `find` already removes overlaps, but guard defensively so a
        // stray overlapping finding can never panic the slice below.
        if f.byte_pos < cursor {
            continue;
        }
        out.push_str(&s[cursor..f.byte_pos]);
        out.push_str(&format!("[REDACTED:{}]", f.kind));
        cursor = f.byte_pos + f.value.len();
    }
    out.push_str(&s[cursor..]);
    out
}

// --- per-kind scanners ---------------------------------------------------

fn scan_emails(s: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'@' {
            // walk left for local-part
            let mut start = i;
            while start > 0 && is_email_local(bytes[start - 1]) {
                start -= 1;
            }
            // walk right for domain
            let mut end = i + 1;
            while end < bytes.len() && is_email_domain(bytes[end]) {
                end += 1;
            }
            if start < i && end > i + 1 && s[i + 1..end].contains('.') {
                out.push(Finding {
                    kind: "email",
                    value: s[start..end].to_string(),
                    byte_pos: start,
                });
            }
        }
    }
    out
}

fn is_email_local(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'%' | b'+' | b'-')
}
fn is_email_domain(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-')
}

fn scan_phones(s: &str) -> Vec<Finding> {
    // Matches `(NNN) NNN-NNNN`, `NNN-NNN-NNNN`, `NNN.NNN.NNNN`,
    // `+1 NNN-NNN-NNNN`. Implemented as a small state machine over
    // digit-or-separator tokens.
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        let digit_chunk = |i: usize| {
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            j - i
        };
        // Optional +1
        if bytes[i] == b'+' && i + 1 < bytes.len() && bytes[i + 1] == b'1' {
            i += 2;
            while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'-' || bytes[i] == b'.') {
                i += 1;
            }
        }
        // Optional `(NNN) `
        if i < bytes.len() && bytes[i] == b'(' && i + 4 < bytes.len() && bytes[i + 4] == b')' {
            let in_paren = &bytes[i + 1..i + 4];
            if in_paren.iter().all(|b| b.is_ascii_digit()) {
                i += 5;
                while i < bytes.len() && (bytes[i] == b' ') {
                    i += 1;
                }
                let mid = digit_chunk(i);
                if mid == 3 && i + 3 < bytes.len() && matches!(bytes[i + 3], b'-' | b'.' | b' ') {
                    let last_start = i + 4;
                    if digit_chunk(last_start) == 4 {
                        out.push(Finding {
                            kind: "phone",
                            value: s[start..last_start + 4].to_string(),
                            byte_pos: start,
                        });
                        i = last_start + 4;
                        continue;
                    }
                }
            }
        }
        // `NNN-NNN-NNNN` or `NNN.NNN.NNNN`
        if digit_chunk(i) == 3 && i + 3 < bytes.len() && matches!(bytes[i + 3], b'-' | b'.') {
            let sep = bytes[i + 3];
            let mid_start = i + 4;
            if digit_chunk(mid_start) == 3
                && mid_start + 3 < bytes.len()
                && bytes[mid_start + 3] == sep
            {
                let last_start = mid_start + 4;
                if digit_chunk(last_start) == 4 {
                    out.push(Finding {
                        kind: "phone",
                        value: s[start..last_start + 4].to_string(),
                        byte_pos: start,
                    });
                    i = last_start + 4;
                    continue;
                }
            }
        }
        i = start + 1;
    }
    out
}

fn scan_ssns(s: &str) -> Vec<Finding> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 11 <= bytes.len() {
        let slice = &bytes[i..i + 11];
        if slice.iter().enumerate().all(|(k, c)| match k {
            3 | 6 => *c == b'-',
            _ => c.is_ascii_digit(),
        }) {
            // Boundary check: avoid taking part of a longer digit run.
            let left_ok = i == 0 || !bytes[i - 1].is_ascii_digit();
            let right_ok = i + 11 == bytes.len() || !bytes[i + 11].is_ascii_digit();
            if left_ok && right_ok {
                out.push(Finding {
                    kind: "ssn",
                    value: s[i..i + 11].to_string(),
                    byte_pos: i,
                });
                i += 11;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn scan_cards(s: &str) -> Vec<Finding> {
    // 13–19 digits, written as digit groups joined by single spaces or
    // dashes (e.g. `4111 1111 1111 1111`, `4111-1111-1111-1111`) or as a
    // single unbroken run. We don't Luhn-check (false positives on
    // phone-like sequences would be worse than missing a few rejects).
    //
    // Cards are matched by accumulating *whole* digit groups: a card never
    // splits a group, and never swallows a separator that bridges into an
    // unrelated trailing number. This keeps a valid card from being lost
    // inside a longer digit/separator run and stops the match from
    // grabbing digits that belong to the following token.
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        let mut digits = 0usize;
        // Byte position just past the last digit included in the card so
        // far (always ends on a digit, never a separator).
        let mut card_end = start;
        let mut j = i;
        loop {
            // Consume one digit group.
            let group_start = j;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            let group_len = j - group_start;
            // Would adding this whole group exceed a card's max length?
            if digits + group_len > 19 {
                break;
            }
            // Once we already hold a complete card (>=13 digits), refuse to
            // absorb a further *short* group (<4 digits). Real card groups
            // are always >=4 digits (Visa/MC 4-4-4-4, Amex 4-6-5), so a
            // trailing 1-3 digit group joined by a space/dash is almost
            // certainly the start of a separate token (a phone area code,
            // an SSN, a year, ...), not part of the card.
            if digits >= 13 && group_len < 4 {
                break;
            }
            digits += group_len;
            card_end = j;
            // Allow a single separator only if it is followed by another
            // digit group (otherwise it is trailing punctuation).
            if j < bytes.len()
                && matches!(bytes[j], b' ' | b'-')
                && j + 1 < bytes.len()
                && bytes[j + 1].is_ascii_digit()
            {
                j += 1;
            } else {
                break;
            }
        }

        if (13..=19).contains(&digits) {
            out.push(Finding {
                kind: "credit_card",
                value: s[start..card_end].to_string(),
                byte_pos: start,
            });
            i = card_end;
        } else {
            // No valid card starting here; skip past the run we examined
            // so we never re-scan the same digits.
            i = j.max(start + 1);
        }
    }
    out
}

fn scan_api_keys(s: &str) -> Vec<Finding> {
    let prefixes: &[&str] = &["sk-", "sk_live_", "sk_test_", "ghp_", "xoxb-", "rk_live_"];
    let mut out = Vec::new();
    for p in prefixes {
        let mut start = 0;
        while let Some(pos) = s[start..].find(p) {
            let abs = start + pos;
            // Greedy match across [A-Za-z0-9_-].
            let bytes = s.as_bytes();
            let mut end = abs + p.len();
            while end < bytes.len()
                && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'_' | b'-'))
            {
                end += 1;
            }
            let tail = end - (abs + p.len());
            if tail >= 16 {
                out.push(Finding {
                    kind: "api_key",
                    value: s[abs..end].to_string(),
                    byte_pos: abs,
                });
            }
            start = end.max(abs + 1);
        }
    }
    out
}
