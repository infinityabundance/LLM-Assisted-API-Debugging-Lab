//! Deterministic rules engine.
//!
//! [`diagnose`] is a pure function over `(name, &[Evidence])`. There is no
//! clock, no env, no fs, and no randomness — which is what makes the
//! `insta` snapshot tests reproducible on any machine.
//!
//! ## How a rule works
//!
//! Each rule is a private function `rule_*(name, evidence, reproduction) ->
//! Option<Diagnosis>`. The rule:
//!
//! 1. Inspects `evidence` for the variants it cares about. If the trigger
//!    pattern is absent, the rule returns `None` and the dispatcher tries
//!    the next rule.
//! 2. If the trigger pattern is present, the rule calls [`pick`] to choose
//!    which evidence items to surface in the rendered output (and in what
//!    order).
//! 3. The rule looks up its prose in `prose.toml` via [`prose`], then
//!    constructs and returns a [`Diagnosis`].
//!
//! ## Why rule order matters
//!
//! Rules are tried in order from most specific (network-layer failure) to
//! least specific (application-layer failure). The dispatcher returns the
//! first match. This matters for inputs where multiple rules could in
//! principle fire — see the test
//! `tls_failure_rule_orders_after_dns_failure` for the canonical example.
//!
//! ## Why prose lives outside this file
//!
//! The hand-written English content (likely-cause templates, hypotheses,
//! unknowns, next-steps, escalation notes, severity rationales) lives in
//! `prose.toml` at the crate root. Editorial changes (a clearer
//! hypothesis, a tighter escalation note) do not require a code change.
//! Logic changes (severity, rule order, evidence patterns) still go here.

use crate::evidence::Evidence;
use crate::prose::prose;
use serde::Serialize;

/// Severity rank assigned to a diagnosis. See [`SeveritySource`] for how a
/// rule arrived at the rank, and the README's "What it does (and does not)
/// claim" section for the ranking philosophy (immediacy of failure, not
/// blast radius).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Lowercase label used in rendered output.
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// How the rule arrived at its severity rank.
///
/// Today every rule reports `AuthorJudgment` because the diagnoser has no
/// visibility into per-customer blast radius — it can only see one
/// transaction at a time. The variant exists so the provenance is explicit
/// in every rendered prompt and report; a reader cannot mistake a
/// hand-assigned rank for a measured impact.
///
/// `DerivedFromEvidence` is reserved for a future variant that would
/// derive severity from evidence values (e.g. `RetryAfterSecs > 60`
/// upgrading rate-limit to High, or a sustained `ConnectionTimeout` count
/// upgrading to Critical). When that variant gets used, the rendered
/// label will say "derived from evidence" instead of "author judgment" —
/// no caller code needs to change.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SeveritySource {
    AuthorJudgment { rationale: String },
    DerivedFromEvidence { rationale: String },
}

impl SeveritySource {
    /// The human-readable rationale, regardless of variant.
    pub fn rationale(&self) -> &str {
        match self {
            SeveritySource::AuthorJudgment { rationale }
            | SeveritySource::DerivedFromEvidence { rationale } => rationale,
        }
    }

    /// Short label distinguishing the two provenance kinds; rendered next
    /// to the severity rank in every output.
    pub fn label(&self) -> &'static str {
        match self {
            SeveritySource::AuthorJudgment { .. } => "author judgment",
            SeveritySource::DerivedFromEvidence { .. } => "derived from evidence",
        }
    }
}

/// The output of [`diagnose`], consumed by every renderer.
///
/// Fields are organized into three groups:
///
/// - **Identification:** `case`, `rule`. The `rule` is a stable string that
///   names the rule arm that fired (e.g. `"dns_failure"`); it is the join
///   key against `prose.toml`.
/// - **Classification:** `severity`, `severity_source`, `likely_cause`. The
///   `likely_cause` is human prose, possibly with a `{host}`/`{peer}`/`{field}`
///   placeholder filled in. `severity_source` carries the provenance.
/// - **Communication:** `evidence`, `hypotheses`, `unknowns`, `next_steps`,
///   `reproduction`, `escalation_note`. These feed both the human report
///   and the LLM prompt. The `evidence` field is a curated subset chosen
///   by [`pick`] in rule order, not the raw input vector.
///
/// `Diagnosis` is `Serialize` so the JSON-envelope prompt renderer can
/// embed it directly without a parallel struct.
#[derive(Debug, Clone, Serialize)]
pub struct Diagnosis {
    pub case: String,
    pub severity: Severity,
    pub severity_source: SeveritySource,
    pub likely_cause: String,
    pub evidence: Vec<Evidence>,
    pub hypotheses: Vec<String>,
    pub unknowns: Vec<String>,
    pub next_steps: Vec<String>,
    pub reproduction: String,
    pub escalation_note: String,
    pub rule: &'static str,
}

/// Diagnose a case by name and the evidence collected for it.
///
/// Rules are matched in a fixed order from most specific (network-layer)
/// to least specific (application-layer); the first matching rule wins.
/// The `unknown` fallback always returns a diagnosis — an unrecognized
/// pattern produces an explicit "no rule matched" diagnosis rather than a
/// silent guess.
///
/// Order is documented in `docs/architecture.md` and pinned by both unit
/// tests (e.g. `dns_failure_wins_over_other_signals`) and proptest
/// invariants (`tests/proptests.rs` proves selection is permutation- and
/// rotation-invariant for any input).
///
/// The `name` parameter is used only for the rendered output (CASE label,
/// reproduction command). Rule selection itself is a pure function of
/// `evidence`.
pub fn diagnose(name: &str, evidence: &[Evidence]) -> Diagnosis {
    // The reproduction command is the same for every rule arm — compute it
    // once and pass by reference.
    let reproduction = format!("cargo run -p llm-assisted-api-debugging-lab -- diagnose {name}");

    // Rule order: network layer first, then transport, then application.
    // Each rule's trigger pattern is documented in its function body.
    if let Some(d) = rule_dns_failure(name, evidence, &reproduction) {
        return d;
    }
    if let Some(d) = rule_tls_failure(name, evidence, &reproduction) {
        return d;
    }
    if let Some(d) = rule_connection_timeout(name, evidence, &reproduction) {
        return d;
    }
    if let Some(d) = rule_webhook_signature(name, evidence, &reproduction) {
        return d;
    }
    if let Some(d) = rule_rate_limit(name, evidence, &reproduction) {
        return d;
    }
    if let Some(d) = rule_auth_missing(name, evidence, &reproduction) {
        return d;
    }
    if let Some(d) = rule_bad_payload(name, evidence, &reproduction) {
        return d;
    }
    // Fallback always fires. By design it returns `Diagnosis`, not
    // `Option<Diagnosis>`, so the dispatcher can never return `None`.
    rule_unknown(name, evidence, &reproduction)
}

/// Construct a `Diagnosis` from the pieces that vary between rules.
///
/// Every rule arm computes the same shape: a severity rank, a curated
/// evidence list, a `likely_cause` string. Everything else (severity
/// rationale, hypotheses, unknowns, next-steps, escalation note) is
/// pulled from `prose.toml` keyed on the rule name. This helper performs
/// that lookup and assembles the `Diagnosis` so each rule arm can stay
/// focused on the parts that are actually rule-specific.
///
/// `rule` doubles as the prose-table key and the `Diagnosis::rule`
/// field, which means a typo in one place is impossible — there is only
/// one place to put it.
fn from_rule(
    name: &str,
    rule: &'static str,
    severity: Severity,
    likely_cause: String,
    pinned_evidence: Vec<Evidence>,
    reproduction: &str,
) -> Diagnosis {
    let p = prose().rule(rule);
    Diagnosis {
        case: name.into(),
        severity,
        severity_source: SeveritySource::AuthorJudgment {
            rationale: p.severity_rationale.clone(),
        },
        likely_cause,
        evidence: pinned_evidence,
        hypotheses: p.hypotheses.clone(),
        unknowns: p.unknowns.clone(),
        next_steps: p.next_steps.clone(),
        reproduction: reproduction.into(),
        escalation_note: p.escalation_note.clone(),
        rule,
    }
}

/// Trigger: any `DnsResolutionFailed` evidence item.
///
/// Severity Critical: name resolution failed before any traffic was sent,
/// so no application-level diagnosis is possible until DNS is restored.
/// Ordered first because every other failure mode presupposes that DNS
/// resolved.
///
/// Pinned evidence order: DNS first (the cause), then `ConnectionTimeout`
/// or `HttpStatus` if either is present (rare in practice — both imply DNS
/// did resolve, but evidence collected from the response side could
/// theoretically include them alongside a context-derived DNS signal).
fn rule_dns_failure(name: &str, ev: &[Evidence], reproduction: &str) -> Option<Diagnosis> {
    // Extract just the host; the message is rendered via the prose
    // template's `{host}` substitution, not directly.
    let host = ev.iter().find_map(|e| match e {
        Evidence::DnsResolutionFailed { host, .. } => Some(host.clone()),
        _ => None,
    })?;
    let pinned = pick(
        ev,
        &[
            |e| matches!(e, Evidence::DnsResolutionFailed { .. }),
            |e| matches!(e, Evidence::ConnectionTimeout { .. }),
            |e| matches!(e, Evidence::HttpStatus(_)),
        ],
    );
    let likely_cause = prose().rule("dns_failure").likely_cause_with_host(&host);
    Some(from_rule(
        name,
        "dns_failure",
        Severity::Critical,
        likely_cause,
        pinned,
        reproduction,
    ))
}

/// Trigger: any `TlsHandshakeFailed` evidence item.
///
/// Severity Critical: TLS failure means no HTTP request was ever
/// transmitted. Like DNS failure, until the transport is restored there
/// is no application-level evidence to reason about.
///
/// Ordered after `dns_failure` because TLS presupposes DNS resolved (a
/// host that doesn't resolve cannot have started a TLS handshake). The
/// test `tls_failure_rule_orders_after_dns_failure` pins this — when both
/// kinds of evidence are present, DNS wins.
fn rule_tls_failure(name: &str, ev: &[Evidence], reproduction: &str) -> Option<Diagnosis> {
    // Extract the peer hostname; the reason is rendered via the prose
    // template's `{peer}` substitution.
    let peer = ev.iter().find_map(|e| match e {
        Evidence::TlsHandshakeFailed { peer, .. } => Some(peer.clone()),
        _ => None,
    })?;
    let pinned = pick(
        ev,
        &[
            |e| matches!(e, Evidence::TlsHandshakeFailed { .. }),
            |e| matches!(e, Evidence::DnsResolutionFailed { .. }),
            |e| matches!(e, Evidence::HttpStatus(_)),
        ],
    );
    let likely_cause = prose().rule("tls_failure").likely_cause_with_peer(&peer);
    Some(from_rule(
        name,
        "tls_failure",
        Severity::Critical,
        likely_cause,
        pinned,
        reproduction,
    ))
}

/// Trigger: any `ConnectionTimeout` evidence item.
///
/// Severity High: the client aborted before any HTTP response was
/// received. The transport opened and the request went out, but no reply
/// came back inside the budget. Severity is High rather than Critical
/// because evidence at this layer still allows the on-call to correlate
/// the failed `request_id` with server-side traces (whereas DNS/TLS
/// failures provide nothing past the transport layer).
fn rule_connection_timeout(name: &str, ev: &[Evidence], reproduction: &str) -> Option<Diagnosis> {
    if !ev
        .iter()
        .any(|e| matches!(e, Evidence::ConnectionTimeout { .. }))
    {
        return None;
    }
    let pinned = pick(
        ev,
        &[
            |e| matches!(e, Evidence::ConnectionTimeout { .. }),
            |e| matches!(e, Evidence::HttpStatus(_)),
        ],
    );
    let likely_cause = prose()
        .rule("connection_timeout")
        .likely_cause_static()
        .to_string();
    Some(from_rule(
        name,
        "connection_timeout",
        Severity::High,
        likely_cause,
        pinned,
        reproduction,
    ))
}

/// Trigger: any `SignatureMismatch` evidence item.
///
/// Severity High: HMAC verification rejected the inbound webhook. The
/// failure is silent in the sense that there is no surfaced error in the
/// customer's application code — the receiver just stops processing
/// events. That class of failure tends to go unnoticed for long stretches.
///
/// Pinned evidence ordering walks the reader through the chain: the HTTP
/// status (the symptom), then the signature mismatch (the diagnoser's
/// observation), then the clock drift and body-mutation signals if
/// present (the two most common upstream causes).
fn rule_webhook_signature(name: &str, ev: &[Evidence], reproduction: &str) -> Option<Diagnosis> {
    if !ev.iter().any(|e| matches!(e, Evidence::SignatureMismatch)) {
        return None;
    }
    let pinned = pick(
        ev,
        &[
            |e| matches!(e, Evidence::HttpStatus(_)),
            |e| matches!(e, Evidence::SignatureMismatch),
            |e| matches!(e, Evidence::ClockDriftSecs { .. }),
            |e| matches!(e, Evidence::BodyMutatedBeforeVerification),
        ],
    );
    let likely_cause = prose()
        .rule("webhook_signature")
        .likely_cause_static()
        .to_string();
    Some(from_rule(
        name,
        "webhook_signature",
        Severity::High,
        likely_cause,
        pinned,
        reproduction,
    ))
}

/// Trigger: `HttpStatus(429)` AND `RetryAfterSecs(_)` together.
///
/// Severity Medium: this is expected back-pressure rather than a service
/// fault. The server explicitly told the client to slow down; the client's
/// retry path is the right place to handle it.
///
/// Both signals are required by design. A bare 429 without `Retry-After`
/// is unusual enough that we'd rather fall through to `unknown` than
/// guess; the test `rate_limit_rule_requires_429_and_retry_after` pins
/// this.
fn rule_rate_limit(name: &str, ev: &[Evidence], reproduction: &str) -> Option<Diagnosis> {
    let has_429 = ev.iter().any(|e| matches!(e, Evidence::HttpStatus(429)));
    let has_retry = ev.iter().any(|e| matches!(e, Evidence::RetryAfterSecs(_)));
    if !(has_429 && has_retry) {
        return None;
    }
    let pinned = pick(
        ev,
        &[
            |e| matches!(e, Evidence::HttpStatus(_)),
            |e| matches!(e, Evidence::RetryAfterSecs(_)),
            |e| matches!(e, Evidence::RateLimitObserved { .. }),
        ],
    );
    let likely_cause = prose().rule("rate_limit").likely_cause_static().to_string();
    Some(from_rule(
        name,
        "rate_limit",
        Severity::Medium,
        likely_cause,
        pinned,
        reproduction,
    ))
}

/// Trigger: `HttpStatus(401)` AND `HeaderMissing { name: "Authorization" }`
/// together.
///
/// Severity Medium: the request was rejected at the auth boundary, but
/// the failure mode is well-understood and almost always a client-side
/// configuration issue (env var unset, secret manager not loaded, proxy
/// stripping the header).
///
/// Both signals are required: a bare 401 without missing Authorization
/// might be a wrong key, an expired token, or many other things that this
/// rule cannot distinguish. The conjunctive trigger keeps the diagnosis
/// honest.
fn rule_auth_missing(name: &str, ev: &[Evidence], reproduction: &str) -> Option<Diagnosis> {
    let has_401 = ev.iter().any(|e| matches!(e, Evidence::HttpStatus(401)));
    let auth_missing = ev
        .iter()
        .any(|e| matches!(e, Evidence::HeaderMissing { name } if name == "Authorization"));
    if !(has_401 && auth_missing) {
        return None;
    }
    let pinned = pick(
        ev,
        &[
            |e| matches!(e, Evidence::HttpStatus(_)),
            |e| matches!(e, Evidence::HeaderMissing { .. }),
        ],
    );
    let likely_cause = prose()
        .rule("auth_missing")
        .likely_cause_static()
        .to_string();
    Some(from_rule(
        name,
        "auth_missing",
        Severity::Medium,
        likely_cause,
        pinned,
        reproduction,
    ))
}

/// Trigger: `HttpStatus(400)` AND `JsonValidationError { .. }` together.
///
/// Severity Low: a single client-side request failed with a structured
/// validation response. The client has all the information it needs to
/// fix the request and retry; nothing else is affected.
///
/// The `field` value (the name of the failing field, if known) is
/// surfaced through the prose template's `{field}` placeholder. If the
/// validation evidence carries no field name, the no-field template is
/// used instead — see `RuleProse::likely_cause_with_optional_field`.
fn rule_bad_payload(name: &str, ev: &[Evidence], reproduction: &str) -> Option<Diagnosis> {
    let has_400 = ev.iter().any(|e| matches!(e, Evidence::HttpStatus(400)));
    let validation = ev.iter().find_map(|e| match e {
        Evidence::JsonValidationError { field, .. } => Some(field.clone()),
        _ => None,
    });
    if !has_400 || validation.is_none() {
        return None;
    }
    // `validation` is `Option<Option<String>>`: the outer is "did we find a
    // JsonValidationError at all", the inner is "did that error name a
    // field". Flatten to drop the outer Some(...) wrapper.
    let field = validation.flatten();
    let pinned = pick(
        ev,
        &[
            |e| matches!(e, Evidence::HttpStatus(_)),
            |e| matches!(e, Evidence::JsonValidationError { .. }),
        ],
    );
    let likely_cause = prose()
        .rule("bad_payload")
        .likely_cause_with_optional_field(field.as_deref());
    Some(from_rule(
        name,
        "bad_payload",
        Severity::Low,
        likely_cause,
        pinned,
        reproduction,
    ))
}

/// Fallback rule: always fires.
///
/// This is the architectural promise that the diagnoser will not silently
/// guess. If no other rule matched, this one produces a diagnosis whose
/// `likely_cause` literally says "Evidence does not match any built-in
/// rule" and whose next-steps tell the reader to add a fixture and a
/// rule for this evidence shape before claiming a diagnosis. Severity
/// Low because the diagnoser has nothing to base a higher rank on, not
/// because the underlying failure is benign — the prose's
/// `severity_rationale` says exactly this.
///
/// Returns `Diagnosis` (not `Option<Diagnosis>`): this is the dispatcher's
/// guarantee that `diagnose()` always returns a value.
fn rule_unknown(name: &str, ev: &[Evidence], reproduction: &str) -> Diagnosis {
    let likely_cause = prose().rule("unknown").likely_cause_static().to_string();
    // The fallback shows every evidence item it received; it has no
    // basis for curating further. Compare against every other rule,
    // which calls `pick()` to surface a curated subset.
    from_rule(
        name,
        "unknown",
        Severity::Low,
        likely_cause,
        ev.to_vec(),
        reproduction,
    )
}

/// Pick evidence items matching the given predicates, in the order the
/// predicates appear, preserving original ordering for ties. Used by
/// every rule arm to choose which evidence to surface in the rendered
/// output (and in what order).
///
/// Predicates are typically `matches!`-driven (e.g.
/// `|e| matches!(e, Evidence::HttpStatus(_))`) so the compiler enforces
/// that the variant name still exists on `Evidence`. This replaced an
/// earlier hand-rolled `u8` tag table that had to be kept in sync with
/// the `Evidence` enum manually — a class of bug the type system can
/// prevent.
///
/// Each evidence item is included at most once even if multiple
/// predicates match; this matters when, e.g., a `webhook_signature` rule
/// pins both `HttpStatus(_)` and `SignatureMismatch` and the input vector
/// could contain ordering edge cases.
fn pick(ev: &[Evidence], predicates: &[fn(&Evidence) -> bool]) -> Vec<Evidence> {
    let mut out = Vec::new();
    for predicate in predicates {
        for e in ev {
            if predicate(e) && !out.contains(e) {
                out.push(e.clone());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn dns_failure_wins_over_other_signals() {
        let ev = vec![
            Evidence::DnsResolutionFailed {
                host: "api.exmaple.com".into(),
                message: "no such host".into(),
            },
            Evidence::HttpStatus(401),
        ];
        let d = diagnose("dns_config", &ev);
        assert_eq!(d.rule, "dns_failure");
        assert_eq!(d.severity, Severity::Critical);
    }

    #[test]
    fn tls_failure_rule_matches() {
        let ev = vec![Evidence::TlsHandshakeFailed {
            peer: "api.example.com".into(),
            reason: "certificate has expired".into(),
        }];
        let d = diagnose("tls_failure", &ev);
        assert_eq!(d.rule, "tls_failure");
        assert_eq!(d.severity, Severity::Critical);
    }

    #[test]
    fn tls_failure_rule_orders_after_dns_failure() {
        // If both DNS and TLS evidence are present, DNS wins (a connection
        // that did not resolve cannot have completed TLS).
        let ev = vec![
            Evidence::DnsResolutionFailed {
                host: "api.example.com".into(),
                message: "no such host".into(),
            },
            Evidence::TlsHandshakeFailed {
                peer: "api.example.com".into(),
                reason: "certificate has expired".into(),
            },
        ];
        let d = diagnose("ambiguous", &ev);
        assert_eq!(d.rule, "dns_failure");
    }

    #[test]
    fn connection_timeout_rule_matches() {
        let ev = vec![Evidence::ConnectionTimeout {
            elapsed_ms: 5012,
            timeout_ms: 5000,
        }];
        let d = diagnose("timeout", &ev);
        assert_eq!(d.rule, "connection_timeout");
        assert_eq!(d.severity, Severity::High);
    }

    #[test]
    fn webhook_signature_rule_matches() {
        let ev = vec![
            Evidence::HttpStatus(401),
            Evidence::SignatureMismatch,
            Evidence::ClockDriftSecs {
                observed: 360,
                tolerance_secs: 300,
            },
            Evidence::BodyMutatedBeforeVerification,
        ];
        let d = diagnose("webhook_signature", &ev);
        assert_eq!(d.rule, "webhook_signature");
        assert_eq!(d.severity, Severity::High);
    }

    #[test]
    fn rate_limit_rule_requires_429_and_retry_after() {
        let with_retry = vec![Evidence::HttpStatus(429), Evidence::RetryAfterSecs(12)];
        assert_eq!(diagnose("rate_limit", &with_retry).rule, "rate_limit");

        // 429 alone (no Retry-After) should not match the rule and falls to unknown.
        let without_retry = vec![Evidence::HttpStatus(429)];
        assert_eq!(diagnose("rate_limit", &without_retry).rule, "unknown");
    }

    #[test]
    fn auth_missing_rule_matches() {
        let ev = vec![
            Evidence::HttpStatus(401),
            Evidence::HeaderMissing {
                name: "Authorization".into(),
            },
        ];
        let d = diagnose("auth_missing", &ev);
        assert_eq!(d.rule, "auth_missing");
        assert_eq!(d.severity, Severity::Medium);
    }

    #[test]
    fn bad_payload_rule_matches() {
        let ev = vec![
            Evidence::HttpStatus(400),
            Evidence::JsonValidationError {
                field: Some("amount".into()),
                message: "Expected integer, got string.".into(),
            },
        ];
        let d = diagnose("bad_payload", &ev);
        assert_eq!(d.rule, "bad_payload");
        assert!(d.likely_cause.contains("`amount`"));
    }

    #[test]
    fn unknown_pattern_does_not_invent_a_cause() {
        let ev = vec![Evidence::HttpStatus(418)];
        let d = diagnose("teapot", &ev);
        assert_eq!(d.rule, "unknown");
        assert!(d.likely_cause.contains("does not match"));
    }
}
