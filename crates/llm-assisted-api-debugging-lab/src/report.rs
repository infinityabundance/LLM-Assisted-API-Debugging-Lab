//! Human-readable report renderer.
//!
//! Pure: takes a [`Diagnosis`], returns a `String`. No I/O. Output
//! formats — both the full report ([`render_report`]) and the short
//! summary used by the `diagnose` subcommand ([`render_short`]) — are
//! pinned by snapshot tests under
//! `crates/llm-assisted-api-debugging-lab/tests/snapshots/`.
//!
//! ## Why no sanitization here
//!
//! Unlike [`crate::llm_prompt`], this module deliberately does **not**
//! pass evidence through a sanitizer. These outputs are read by humans
//! (in a terminal, in an escalation queue), not fed to a model. A
//! human reader benefits from seeing the literal log message exactly
//! as it appeared, including any newlines or backticks; a model would
//! be vulnerable to that same content as injection. The split is
//! intentional and load-bearing — see `docs/llm_assisted_workflow.md`
//! for the threat model.

use crate::diagnose::Diagnosis;
use crate::evidence::Evidence;
use std::fmt::Write;

/// Compact one-screen summary used by the `diagnose` subcommand.
///
/// Includes case, rule, severity (rank + provenance label only — the
/// full rationale is left to [`render_report`]), likely cause, the
/// pinned evidence list, and the reproduction command. Omits
/// hypotheses, unknowns, next-steps, and the escalation note. The
/// `diagnose` subcommand is the most-shown surface (first command in
/// `scripts/run_demo.sh`), so the output is intentionally short.
pub fn render_short(d: &Diagnosis) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "CASE: {}", d.case);
    let _ = writeln!(s, "RULE: {}", d.rule);
    let _ = writeln!(
        s,
        "SEVERITY: {} ({})",
        d.severity.as_str(),
        d.severity_source.label()
    );
    let _ = writeln!(s, "LIKELY CAUSE: {}", d.likely_cause);
    if !d.evidence.is_empty() {
        s.push_str("EVIDENCE:\n");
        for e in &d.evidence {
            let _ = writeln!(s, "- {}", render_evidence(e));
        }
    }
    let _ = writeln!(s, "REPRODUCTION:\n{}", d.reproduction);
    s
}

/// Full human-readable report for the `report` subcommand.
///
/// Includes everything `render_short` shows plus the severity rationale,
/// hypotheses, unknowns, ordered next-steps, and the escalation note.
/// The same `Diagnosis` data is presented; this just shows more of it.
///
/// Section order mirrors `render_prompt` so a reader who has seen one
/// can navigate the other instinctively. Section labels distinguish the
/// two: report headers are bare (`HYPOTHESES`); prompt headers carry
/// instructions (`HYPOTHESES (consistent with evidence; may be true or
/// false):`).
pub fn render_report(d: &Diagnosis) -> String {
    let mut s = String::new();

    let _ = writeln!(s, "CASE: {}", d.case);
    let _ = writeln!(s, "RULE: {}", d.rule);
    let _ = writeln!(
        s,
        "SEVERITY: {} ({}: {})",
        d.severity.as_str(),
        d.severity_source.label(),
        d.severity_source.rationale()
    );
    let _ = writeln!(s, "LIKELY CAUSE: {}", d.likely_cause);
    s.push('\n');

    s.push_str("EVIDENCE:\n");
    if d.evidence.is_empty() {
        s.push_str("- (none collected)\n");
    } else {
        for e in &d.evidence {
            let _ = writeln!(s, "- {}", render_evidence(e));
        }
    }
    s.push('\n');

    s.push_str("HYPOTHESES (consistent with evidence; not asserted as fact):\n");
    if d.hypotheses.is_empty() {
        s.push_str("- (none)\n");
    } else {
        for h in &d.hypotheses {
            let _ = writeln!(s, "- {h}");
        }
    }
    s.push('\n');

    s.push_str("UNKNOWNS (do not invent answers):\n");
    if d.unknowns.is_empty() {
        s.push_str("- (none)\n");
    } else {
        for u in &d.unknowns {
            let _ = writeln!(s, "- {u}");
        }
    }
    s.push('\n');

    let _ = writeln!(s, "REPRODUCTION:\n{}\n", d.reproduction);

    s.push_str("NEXT STEPS:\n");
    for (i, step) in d.next_steps.iter().enumerate() {
        let _ = writeln!(s, "{}. {}", i + 1, step);
    }
    s.push('\n');

    let _ = write!(s, "ESCALATION NOTE:\n{}\n", d.escalation_note);

    s
}

/// Format a single [`Evidence`] item as one line of human-readable text.
///
/// This is also the input to [`crate::llm_prompt::sanitize_for_prompt`]:
/// the prompt renderers call `render_evidence` then sanitize the result.
/// Keeping a single rendering path means a wording change to evidence
/// surfaces consistently in both human and prompt output.
///
/// Pure: no I/O, deterministic for any input variant.
pub fn render_evidence(e: &Evidence) -> String {
    match e {
        Evidence::HttpStatus(code) => format!("HTTP status: {code}"),
        Evidence::HeaderPresent { name, value } => match value {
            Some(v) => format!("Request header present: {name} = {v}"),
            None => format!("Request header present: {name}"),
        },
        Evidence::HeaderMissing { name } => {
            format!("Request header missing: {name}")
        }
        Evidence::BodyMutatedBeforeVerification => {
            "Request body was modified by middleware before verification.".into()
        }
        Evidence::SignatureMismatch => "HMAC signature verification failed.".into(),
        Evidence::ClockDriftSecs {
            observed,
            tolerance_secs,
        } => format!("Clock drift {observed}s exceeds tolerance {tolerance_secs}s."),
        Evidence::RetryAfterSecs(secs) => format!("Retry-After header: {secs}s"),
        Evidence::RateLimitObserved {
            observed_rps,
            limit_rps,
        } => format!("Observed rate {observed_rps} rps exceeds account limit {limit_rps} rps."),
        Evidence::DnsResolutionFailed { host, message } => {
            format!("DNS resolution failed for {host}: {message}")
        }
        Evidence::TlsHandshakeFailed { peer, reason } => {
            format!("TLS handshake to {peer} failed: {reason}")
        }
        Evidence::ConnectionTimeout {
            elapsed_ms,
            timeout_ms,
        } => format!("Client timeout: aborted after {elapsed_ms}ms (timeout {timeout_ms}ms)."),
        Evidence::JsonValidationError { field, message } => match field {
            Some(f) => format!("JSON validation error on field `{f}`: {message}"),
            None => format!("JSON validation error: {message}"),
        },
    }
}
