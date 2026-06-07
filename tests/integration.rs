use regex_pii_rs::{find, redact};

#[test]
fn finds_emails() {
    let s = "Reach jane.doe@example.com";
    let hits = find(s);
    assert!(hits
        .iter()
        .any(|f| f.kind == "email" && f.value == "jane.doe@example.com"));
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

#[test]
fn api_key_digits_not_reported_as_card() {
    // The all-digit tail of an API key must not surface as a second,
    // nested `credit_card` finding.
    let s = "token=sk_live_4111111111111111";
    let hits = find(s);
    assert_eq!(hits.len(), 1, "expected exactly one finding, got {hits:?}");
    assert_eq!(hits[0].kind, "api_key");
    assert!(!hits.iter().any(|f| f.kind == "credit_card"));
    assert_eq!(redact(s), "token=[REDACTED:api_key]");
}

#[test]
fn phone_inside_card_span_not_double_reported() {
    // A phone-shaped run inside a credit-card span is part of the card,
    // not a separate finding.
    let s = "Card 4111 555-123-4567 ok";
    let hits = find(s);
    assert_eq!(hits.len(), 1, "expected one finding, got {hits:?}");
    assert_eq!(hits[0].kind, "credit_card");
}

#[test]
fn finds_card_digits() {
    let s = "pay 4111 1111 1111 1111 now";
    let hits = find(s);
    assert!(hits
        .iter()
        .any(|f| f.kind == "credit_card" && f.value == "4111 1111 1111 1111"));
}

#[test]
fn finds_paren_phone() {
    let s = "Call (555) 123-4567 today";
    let hits = find(s);
    assert!(hits
        .iter()
        .any(|f| f.kind == "phone" && f.value == "(555) 123-4567"));
}

#[test]
fn redact_preserves_non_pii_and_multibyte() {
    let s = "café jane@example.com ☕";
    assert_eq!(redact(s), "café [REDACTED:email] ☕");
}

#[test]
fn multiple_findings_sorted_by_position() {
    let s = "a@b.com and 123-45-6789 end";
    let hits = find(s);
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].kind, "email");
    assert_eq!(hits[1].kind, "ssn");
    assert!(hits[0].byte_pos < hits[1].byte_pos);
}
