//! Evidence model and collectors.
//!
//! Evidence is the only input the rules engine consumes. Cases and log
//! lines are normalized into [`Evidence`] items here; `diagnose()` never
//! reads a [`Case`] or a raw log line directly. That separation is what
//! keeps the rules engine a pure function over evidence.
//!
//! Two collection paths exist:
//!
//! - [`collect_evidence`] takes a `Case` plus the contents of its log
//!   file and produces the union, with cross-source dedup (see
//!   [`is_redundant_with`] below).
//! - [`parse_log`] takes only a log string and is used by the
//!   `diagnose-log` subcommand for ad-hoc analysis when no JSON case is
//!   available. The log markers it recognizes are documented in
//!   `docs/architecture.md`.

use crate::cases::Case;
use serde::Serialize;

/// A single normalized signal extracted from a request/response, env
/// context, or a log line.
///
/// Variants are intentionally narrow: each one corresponds to a fact a
/// support engineer would write in an escalation note. Inference belongs
/// in `diagnose()`, not here. If you find yourself wanting to add a
/// variant whose name is a hypothesis ("PossibleAuthMisconfig"), it
/// belongs in `prose.toml` as a hypothesis string for an existing rule,
/// not as new evidence.
///
/// `Serialize` so the JSON-envelope prompt renderer can emit each variant
/// directly. The `#[serde(tag = "kind")]` attribute means each variant
/// serializes as `{"kind": "VariantName", ...fields}`, which gives every
/// variant a stable JSON discriminator without writing a hand-rolled
/// serializer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind")]
pub enum Evidence {
    /// Final HTTP status code observed on the response. Absent for
    /// connection-layer failures (DNS, TLS, timeout) where no response
    /// was received.
    HttpStatus(u16),
    /// A request header that was present. The `value` is masked (e.g.
    /// `"***"` for `Authorization`) — we don't surface secret material in
    /// rendered output.
    HeaderPresent { name: String, value: Option<String> },
    /// A request header that the rule was looking for but did not find.
    /// Currently produced only for `Authorization` (used by the
    /// `auth_missing` rule).
    HeaderMissing { name: String },
    /// The request body was modified by middleware between transmission
    /// and verification. The webhook signature rule cares about this
    /// because re-encoding even idempotent JSON changes the byte stream
    /// that HMAC was computed over.
    BodyMutatedBeforeVerification,
    /// HMAC signature verification failed. Sourced from log markers
    /// `reason=signature_mismatch` or `signature verification failed`.
    SignatureMismatch,
    /// Clock skew between the signature timestamp and the server clock,
    /// expressed in absolute seconds (`observed.abs()`). Only emitted
    /// when the magnitude exceeds `tolerance_secs`. Sign is dropped to
    /// keep dedup simple — `|skew| > tol` is what the verifier checks.
    ClockDriftSecs { observed: i64, tolerance_secs: u64 },
    /// Server-supplied `Retry-After` value in seconds, parsed from the
    /// response header.
    RetryAfterSecs(u64),
    /// Observed request rate vs the account's documented per-second
    /// limit, sourced from log markers like `burst above limit
    /// observed_rps=X limit_rps=Y`.
    RateLimitObserved { observed_rps: u32, limit_rps: u32 },
    /// DNS resolution failed for the given host. Both fields are required
    /// when this is emitted from a log line — see the parser comments
    /// for why an abort line without `host=` is intentionally skipped.
    DnsResolutionFailed { host: String, message: String },
    /// TLS handshake to the given peer failed before any HTTP request was
    /// sent. Same parser-strictness contract as `DnsResolutionFailed`:
    /// the marker substring without a `peer=` token is descriptive
    /// prose, not a fresh observation.
    TlsHandshakeFailed { peer: String, reason: String },
    /// The client aborted the request because the upstream did not
    /// respond inside the budget. Both fields together prove the abort
    /// was on the client side (elapsed >= timeout).
    ConnectionTimeout { elapsed_ms: u64, timeout_ms: u64 },
    /// Server-side schema validation rejected the request. `field` is the
    /// failing field name when the server identified one (most common);
    /// `message` is the validation error string.
    JsonValidationError {
        field: Option<String>,
        message: String,
    },
}

/// Collect evidence from a [`Case`] and the contents of its log file.
///
/// Deterministic source order is preserved: context first (environmental
/// facts the caller observed), then response, then request, then
/// log-derived items. This ordering matters for two reasons:
///
/// 1. **Snapshot stability.** The renderers walk the vec in order, so
///    consistent input order produces consistent output for `cargo insta`.
/// 2. **Dedup priority.** When two sources describe the same fact (e.g.
///    a DNS error appearing in both `case.context.dns_error` and the
///    log's `error="..."` field), the *first*-pushed item wins because
///    [`is_redundant_with`] treats the candidate as redundant against
///    `existing`. Pushing context first means the more authoritative
///    caller-side error string is kept.
pub fn collect_evidence(case: &Case, log_text: &str) -> Vec<Evidence> {
    let mut out = Vec::new();

    // ---- Context evidence (environmental, from the caller's vantage) ----

    // DNS failure means the connection never opened. We accept either
    // `dns_resolved: false` alone (with placeholder strings) or that plus
    // the more specific `dns_host` and `dns_error` fields.
    if matches!(case.context.dns_resolved, Some(false)) {
        let host = case
            .context
            .dns_host
            .clone()
            .unwrap_or_else(|| "<unknown host>".into());
        let message = case
            .context
            .dns_error
            .clone()
            .unwrap_or_else(|| "name resolution failed".into());
        out.push(Evidence::DnsResolutionFailed { host, message });
    }

    if matches!(case.context.tls_handshake_failed, Some(true)) {
        let peer = case
            .context
            .tls_peer
            .clone()
            .unwrap_or_else(|| "<unknown peer>".into());
        let reason = case
            .context
            .tls_failure_reason
            .clone()
            .unwrap_or_else(|| "tls handshake failed".into());
        out.push(Evidence::TlsHandshakeFailed { peer, reason });
    }

    // No response received AND elapsed time crossed the configured
    // timeout: the client gave up before the server replied. Both halves
    // of the conjunction matter — `response.is_none()` alone could mean
    // DNS or TLS failed (handled above), and `elapsed >= timeout` alone
    // would mis-fire on a slow-but-completed request.
    if case.response.is_none() {
        if let (Some(elapsed), Some(timeout)) = (
            case.context.elapsed_ms_before_abort,
            case.request.timeout_ms,
        ) {
            if elapsed >= timeout {
                out.push(Evidence::ConnectionTimeout {
                    elapsed_ms: elapsed,
                    timeout_ms: timeout,
                });
            }
        }
    }

    // Clock drift only matters if the case is signature-bearing (a
    // tolerance is configured) AND the magnitude exceeds it. We store the
    // absolute value so dedup against the log-derived item works
    // structurally regardless of which side observed the skew.
    if let (Some(skew), Some(tol)) = (
        case.context.client_clock_skew_secs,
        case.context.signature_tolerance_secs,
    ) {
        if skew.unsigned_abs() > tol {
            out.push(Evidence::ClockDriftSecs {
                observed: skew.abs(),
                tolerance_secs: tol,
            });
        }
    }

    if matches!(case.context.body_mutated_before_verification, Some(true)) {
        out.push(Evidence::BodyMutatedBeforeVerification);
    }

    // ---- Response evidence (only if a response was received) ----
    if let Some(resp) = &case.response {
        out.push(Evidence::HttpStatus(resp.status));

        // Retry-After is only meaningful when present and parseable as
        // unsigned seconds. The HTTP spec also allows an HTTP-date form;
        // we don't currently parse that because none of the fixtures use
        // it and a real on-call would notice if a server started sending
        // dates instead of ints.
        if let Some(retry_after) = resp.headers.get("Retry-After") {
            if let Ok(n) = retry_after.parse::<u64>() {
                out.push(Evidence::RetryAfterSecs(n));
            }
        }

        // Server's structured validation response is parsed for the
        // failing field name, which the bad_payload rule surfaces in its
        // likely-cause text via `{field}` substitution.
        if let Some(err) = parse_validation_error_body(&resp.body_summary) {
            out.push(err);
        }
    }

    // ---- Request evidence ----
    //
    // We currently care about exactly one header: Authorization. The
    // present/missing distinction drives the auth_missing rule. If we
    // ever start checking other headers (Idempotency-Key, X-Signature),
    // factor this into a small loop.
    let auth_header = "Authorization";
    if case.request.headers.contains_key(auth_header) {
        out.push(Evidence::HeaderPresent {
            name: auth_header.into(),
            value: Some("***".into()),
        });
    } else {
        out.push(Evidence::HeaderMissing {
            name: auth_header.into(),
        });
    }

    // ---- Log-derived evidence ----
    //
    // Dedup is structural for most variants (full equality via
    // `out.contains`); for `JsonValidationError`, `DnsResolutionFailed`,
    // and `TlsHandshakeFailed`, the dedup keys on a stable identifier
    // (field name / host / peer) because the body parser and log parser
    // emit the same fact with slightly different message text. See
    // [`is_redundant_with`].
    for ev in parse_log(log_text) {
        if is_redundant_with(&out, &ev) {
            continue;
        }
        out.push(ev);
    }

    out
}

/// Decide whether `candidate` is already represented in `existing`.
///
/// For most variants this is plain structural equality (`Vec::contains`).
/// Three variants need a richer notion of "same fact":
///
/// - `JsonValidationError` — body parser and log parser typically produce
///   the same field with different error messages. Showing both would
///   misleadingly suggest two independent errors.
/// - `DnsResolutionFailed` — context (caller-side) and log (service-side)
///   both describe the same lookup; we want one rendered line per host.
/// - `TlsHandshakeFailed` — same shape as DNS, by symmetry.
///
/// In all three cases the *first* item pushed wins, which is the
/// context-derived one (see `collect_evidence`'s source order). That's
/// the more authoritative source: it's the error string the caller's
/// network stack actually saw.
fn is_redundant_with(existing: &[Evidence], candidate: &Evidence) -> bool {
    if existing.contains(candidate) {
        return true;
    }
    match candidate {
        Evidence::JsonValidationError { field, .. } => existing.iter().any(|e| {
            matches!(
                e,
                Evidence::JsonValidationError { field: f, .. } if f == field
            )
        }),
        Evidence::DnsResolutionFailed { host, .. } => existing.iter().any(|e| {
            matches!(
                e,
                Evidence::DnsResolutionFailed { host: h, .. } if h == host
            )
        }),
        Evidence::TlsHandshakeFailed { peer, .. } => existing.iter().any(|e| {
            matches!(
                e,
                Evidence::TlsHandshakeFailed { peer: p, .. } if p == peer
            )
        }),
        _ => false,
    }
}

/// Parse a log buffer into evidence items by scanning for known markers.
///
/// The parser is deliberately substring-based, not regex-driven: the
/// markers it recognizes are documented in `docs/architecture.md`, and
/// adding a new marker should be a one-line change. The cost of that
/// simplicity is that the parser does not understand log-line *structure*
/// (level, component, timestamp) — it only checks whether specific
/// substrings appear and pulls `key=value` pairs out of the surrounding
/// text via [`extract_kv_str`].
///
/// This is also the public entry point for the `diagnose-log` subcommand,
/// which accepts a bare log file with no JSON case fixture. Evidence
/// extracted here is identical to what `collect_evidence` would extract
/// from the same log; only the context-derived items (DNS state, clock
/// skew, etc.) are missing.
pub fn parse_log(log_text: &str) -> Vec<Evidence> {
    let mut out = Vec::new();
    for raw_line in log_text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        if line.contains("reason=signature_mismatch")
            || line.contains("signature verification failed")
        {
            push_unique(&mut out, Evidence::SignatureMismatch);
        }

        if line.contains("body_modified=true") || line.contains("body_mutated=true") {
            push_unique(&mut out, Evidence::BodyMutatedBeforeVerification);
        }

        if let (Some(observed), Some(tol)) = (
            extract_kv_i64(line, "drift_secs"),
            extract_kv_u64(line, "tolerance_secs"),
        ) {
            push_unique(
                &mut out,
                Evidence::ClockDriftSecs {
                    observed: observed.abs(),
                    tolerance_secs: tol,
                },
            );
        }

        if line.contains("schema validation failed") {
            let field = extract_kv_str(line, "field");
            push_unique(
                &mut out,
                Evidence::JsonValidationError {
                    field,
                    message: "schema validation failed".into(),
                },
            );
        }

        if line.contains("burst above limit") {
            if let Some(retry) = extract_kv_u64(line, "retry_after_secs") {
                push_unique(&mut out, Evidence::RetryAfterSecs(retry));
            }
            if let (Some(observed), Some(limit)) = (
                extract_kv_u32(line, "observed_rps"),
                extract_kv_u32(line, "limit_rps"),
            ) {
                push_unique(
                    &mut out,
                    Evidence::RateLimitObserved {
                        observed_rps: observed,
                        limit_rps: limit,
                    },
                );
            }
        }

        // Only emit if the line carries a `host=` token. An abort line that
        // mentions DNS resolution as descriptive prose (no `host=`) is not a
        // fresh observation — emitting a `<unknown host>` placeholder would
        // produce a phantom evidence line that the dedup keys cannot
        // collapse against the real one.
        if line.contains("name resolution failed") {
            if let Some(host) = extract_kv_str(line, "host") {
                let message =
                    extract_kv_str(line, "error").unwrap_or_else(|| "no such host".into());
                push_unique(&mut out, Evidence::DnsResolutionFailed { host, message });
            }
        }

        // Same shape as the DNS rule above: an abort line carrying the
        // marker substring as prose (e.g. `aborting request: tls handshake
        // failed`) without a `peer=` token is not new evidence.
        if line.contains("tls handshake failed") {
            if let Some(peer) = extract_kv_str(line, "peer") {
                let reason =
                    extract_kv_str(line, "error").unwrap_or_else(|| "tls handshake failed".into());
                push_unique(&mut out, Evidence::TlsHandshakeFailed { peer, reason });
            }
        }

        if line.contains("upstream timeout") {
            if let (Some(elapsed), Some(timeout)) = (
                extract_kv_u64(line, "elapsed_ms"),
                extract_kv_u64(line, "timeout_ms"),
            ) {
                push_unique(
                    &mut out,
                    Evidence::ConnectionTimeout {
                        elapsed_ms: elapsed,
                        timeout_ms: timeout,
                    },
                );
            }
        }
    }
    out
}

/// Push `ev` only if an exactly-equal item is not already present.
///
/// This is for *within-log* dedup (the same marker can appear on
/// multiple lines, e.g. a verifier logging both DEBUG and WARN for the
/// same signature mismatch). Cross-source dedup (context vs log) lives
/// in [`is_redundant_with`] and uses richer keys.
fn push_unique(out: &mut Vec<Evidence>, ev: Evidence) {
    if !out.contains(&ev) {
        out.push(ev);
    }
}

/// Parse a server response body for a structured validation error.
///
/// Recognizes the shape:
/// `{"error": {"code": "validation_failed", "field": "...", "message": "..."}}`
///
/// Returns `None` for any other body shape, including bodies that are not
/// valid JSON at all. The caller (`collect_evidence`) treats `None` as
/// "no evidence to add" rather than as a parse error — bodies like
/// `{"error":"unauthorized"}` are perfectly normal, they just don't
/// produce a `JsonValidationError`.
fn parse_validation_error_body(body: &str) -> Option<Evidence> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let err = value.get("error")?;
    let code = err.get("code")?.as_str()?;
    if code == "validation_failed" {
        let field = err
            .get("field")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let message = err
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("validation failed")
            .to_string();
        Some(Evidence::JsonValidationError { field, message })
    } else {
        None
    }
}

/// Extract `key=value` where the value is either a `"quoted string"` or an
/// unquoted whitespace-delimited token.
///
/// The match requires a word boundary *before* the key (start of line or a
/// whitespace character) so that `prefixed_key=...` does not match a search
/// for `key`. The trailing `=` in the search needle implicitly bounds the
/// key on the right side, so `keyword=...` does not match a search for
/// `key` either. This is the only protection we have against substring
/// collisions; it is intentionally simple, and its limits are documented in
/// `docs/architecture.md`.
fn extract_kv_str(line: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    let mut search_from = 0;
    let start = loop {
        let rel = line[search_from..].find(&needle)?;
        let abs = search_from + rel;
        let preceded_by_boundary = abs == 0
            || line[..abs]
                .chars()
                .next_back()
                .is_some_and(char::is_whitespace);
        if preceded_by_boundary {
            break abs + needle.len();
        }
        search_from = abs + 1;
    };
    let rest = &line[start..];
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(stripped[..end].to_string())
    } else {
        let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }
}

// Numeric variants of `extract_kv_str`. `Option<T>` is `None` when the
// key is absent OR when the value fails to parse as the requested
// integer type. Callers treat both cases as "no signal," so we don't
// distinguish them. A `<T: FromStr>` generic would collapse these into
// one function but at the cost of explicit type annotations at every
// call site; three tiny helpers read more cleanly here.

fn extract_kv_u64(line: &str, key: &str) -> Option<u64> {
    extract_kv_str(line, key).and_then(|s| s.parse().ok())
}

fn extract_kv_u32(line: &str, key: &str) -> Option<u32> {
    extract_kv_str(line, key).and_then(|s| s.parse().ok())
}

fn extract_kv_i64(line: &str, key: &str) -> Option<i64> {
    extract_kv_str(line, key).and_then(|s| s.parse().ok())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn parse_log_extracts_signature_mismatch_and_drift() {
        let log = "2026-05-11T08:04:40.005Z DEBUG webhook.verify msg=\"computing HMAC\" \
                   drift_secs=360 tolerance_secs=300\n\
                   2026-05-11T08:04:40.006Z WARN webhook.verify \
                   msg=\"signature verification failed\" reason=signature_mismatch";
        let ev = parse_log(log);
        assert!(ev.contains(&Evidence::SignatureMismatch));
        assert!(ev.contains(&Evidence::ClockDriftSecs {
            observed: 360,
            tolerance_secs: 300
        }));
    }

    #[test]
    fn parse_log_extracts_dns_failure() {
        let log = "2026-05-11T08:08:20.140Z ERROR http.client \
                   msg=\"name resolution failed\" host=api.exmaple.com error=\"no such host\"";
        let ev = parse_log(log);
        assert_eq!(
            ev,
            vec![Evidence::DnsResolutionFailed {
                host: "api.exmaple.com".into(),
                message: "no such host".into(),
            }]
        );
    }

    #[test]
    fn parse_log_extracts_rate_limit_burst() {
        let log = "2026-05-11T08:03:20.000Z WARN ratelimit msg=\"burst above limit\" \
                   account=acct_*** observed_rps=112 limit_rps=100 retry_after_secs=12";
        let ev = parse_log(log);
        assert!(ev.contains(&Evidence::RetryAfterSecs(12)));
        assert!(ev.contains(&Evidence::RateLimitObserved {
            observed_rps: 112,
            limit_rps: 100
        }));
    }

    #[test]
    fn parse_log_extracts_timeout() {
        let log = "2026-05-11T08:06:45.012Z WARN http.client msg=\"upstream timeout\" \
                   elapsed_ms=5012 timeout_ms=5000";
        let ev = parse_log(log);
        assert_eq!(
            ev,
            vec![Evidence::ConnectionTimeout {
                elapsed_ms: 5012,
                timeout_ms: 5000
            }]
        );
    }

    #[test]
    fn parse_log_extracts_validation_error() {
        let log = "2026-05-11T08:01:40.022Z WARN charges.handler \
                   msg=\"schema validation failed\" field=amount expected=integer got=string";
        let ev = parse_log(log);
        assert_eq!(
            ev,
            vec![Evidence::JsonValidationError {
                field: Some("amount".into()),
                message: "schema validation failed".into(),
            }]
        );
    }

    // -- Negative coverage for the substring kv-extractor below.

    #[test]
    fn extract_kv_handles_quoted_value_with_spaces() {
        // The trailing key after a quoted value must still parse correctly.
        let line = "msg=\"value with spaces\" host=example.com";
        assert_eq!(
            extract_kv_str(line, "msg"),
            Some("value with spaces".into())
        );
        assert_eq!(extract_kv_str(line, "host"), Some("example.com".into()));
    }

    #[test]
    fn extract_kv_returns_none_for_absent_key() {
        let line = "host=example.com retry_after_secs=5";
        assert_eq!(extract_kv_str(line, "absent"), None);
        assert_eq!(extract_kv_u64(line, "absent"), None);
    }

    #[test]
    fn extract_kv_rejects_malformed_numerics() {
        let line = "elapsed_ms=oops timeout_ms=not_a_number";
        assert_eq!(extract_kv_u64(line, "elapsed_ms"), None);
        assert_eq!(extract_kv_u64(line, "timeout_ms"), None);
    }

    #[test]
    fn extract_kv_does_not_match_inside_a_longer_key() {
        // Searching for `key` must not match `prefixed_key=`. This is the
        // word-boundary guarantee in extract_kv_str.
        let line = "prefixed_key=should_not_match key=found";
        assert_eq!(extract_kv_str(line, "key"), Some("found".into()));
    }

    #[test]
    fn parse_log_ignores_blank_and_unknown_lines() {
        let log = "\n\n\
                   2026-05-11T08:00:00.000Z INFO http.server msg=\"healthz ok\"\n\
                   \n";
        // No recognized markers: result is empty.
        assert!(parse_log(log).is_empty());
    }

    #[test]
    fn parse_log_does_not_emit_phantom_tls_for_abort_line() {
        // The "aborting request: tls handshake failed" line carries the
        // marker substring as prose, not as a fresh observation: it has no
        // `peer=` token. The parser must skip it rather than emit a
        // <unknown peer> placeholder that the dedup cannot collapse.
        let log = "2026-05-11T08:11:40.142Z ERROR http.client msg=\"tls handshake failed\" peer=api.example.com error=\"certificate has expired\"\n\
                   2026-05-11T08:11:40.156Z WARN  http.client msg=\"aborting request: tls handshake failed\" elapsed_ms=156";
        let ev = parse_log(log);
        assert_eq!(
            ev,
            vec![Evidence::TlsHandshakeFailed {
                peer: "api.example.com".into(),
                reason: "certificate has expired".into(),
            }],
            "abort line without `peer=` must not produce a second TlsHandshakeFailed"
        );
    }

    #[test]
    fn parse_log_does_not_emit_phantom_dns_for_abort_line() {
        // Symmetric to the TLS test above: an abort line that happens to
        // mention "name resolution failed" without a `host=` token must
        // not produce a <unknown host> placeholder.
        let log = "2026-05-11T08:08:20.140Z ERROR http.client msg=\"name resolution failed\" host=api.exmaple.com error=\"no such host\"\n\
                   2026-05-11T08:08:20.142Z WARN  http.client msg=\"aborting request: name resolution failed\" elapsed_ms=142";
        let ev = parse_log(log);
        assert_eq!(
            ev,
            vec![Evidence::DnsResolutionFailed {
                host: "api.exmaple.com".into(),
                message: "no such host".into(),
            }],
            "abort line without `host=` must not produce a second DnsResolutionFailed"
        );
    }
}
