use regex_pii_rs::{find, redact};

#[test]
fn finds_emails() {
    let s = "Reach jane.doe@example.com";
    let hits = find(s);
    assert!(hits.iter().any(|f| f.kind == "email" && f.value == "jane.doe@example.com"));
}

#[test]
fn finds_dash_phone() {
    let s = "Call 555-123-4567";
    let hits = find(s);
    assert!(hits.iter().any(|f| f.kind == "phone"));
}

#[test]
fn finds_ssn() {
    let s = "SSN 123-45-6789";
    let hits = find(s);
    assert!(hits.iter().any(|f| f.kind == "ssn"));
}

#[test]
fn finds_api_key() {
    let s = "key sk-live-AAAABBBBCCCCDDDDEEEE";
    let hits = find(s);
    assert!(hits.iter().any(|f| f.kind == "api_key"));
}

#[test]
fn redact_replaces_with_typed_token() {
    let s = "to jane@example.com";
    let out = redact(s);
    assert_eq!(out, "to [REDACTED:email]");
}

#[test]
fn clean_text_passes_through() {
    let s = "no pii in this sentence";
    assert!(find(s).is_empty());
    assert_eq!(redact(s), s);
}

#[test]
fn boundary_avoids_partial_ssn() {
    // 12 digits with dashes in SSN positions but extra trailing digit
    // — should NOT match.
    let s = "1234-56-78901";
    let hits = find(s);
    assert!(!hits.iter().any(|f| f.kind == "ssn"));
}
