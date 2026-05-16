# regex-pii-rs

[![crates.io](https://img.shields.io/crates/v/regex-pii-rs.svg)](https://crates.io/crates/regex-pii-rs)

Detect/redact emails, NA-format phones, US SSNs, credit-card-shaped
numbers, prefixed API keys — without the `regex` crate. Rust port of
[`pii-sentry`](https://www.npmjs.com/package/@mukundakatta/pii-sentry).

```rust
use regex_pii_rs::redact;
let out = redact("reach jane@example.com or 555-123-4567");
```

Zero deps. MIT or Apache-2.0.
