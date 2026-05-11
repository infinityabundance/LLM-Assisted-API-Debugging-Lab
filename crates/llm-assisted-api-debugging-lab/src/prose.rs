//! Per-rule prose loader.
//!
//! All editorial content (likely-cause templates, hypotheses, unknowns,
//! next-step bullets, escalation-note copy, severity rationale) lives in
//! `prose.toml` at the crate root, embedded into the binary via
//! `include_str!` and parsed once on first access through `OnceLock`.
//!
//! Rule logic in `diagnose.rs` references prose by rule name; mismatches
//! between the two surface as a panic at first access (during tests,
//! immediately on first use). This is the right severity: a missing prose
//! key or malformed prose.toml is a programming error, not a runtime
//! condition — and the test suite exercises every rule, so any drift fails
//! `cargo test` rather than reaching production. The `clippy::panic`
//! allow below is scoped to this load-time validation surface only.

#![allow(clippy::panic)]

use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::OnceLock;

const PROSE_TOML: &str = include_str!("../prose.toml");

/// Top-level deserialized form of `prose.toml`.
///
/// The TOML file looks like `[rules.<rule_name>] ...`, which deserializes
/// as a single `rules` map keyed on rule name. `BTreeMap` rather than
/// `HashMap` so iteration order during validation tests is stable.
#[derive(Debug, Deserialize)]
pub struct Prose {
    rules: BTreeMap<String, RuleProse>,
}

/// Per-rule prose entry.
///
/// `likely_cause` and the three `likely_cause_template_*` fields are all
/// `Option`; each rule arm uses exactly one of them depending on whether
/// it needs to interpolate a placeholder. The
/// `every_rule_template_kind_matches_its_call_site` test pins which
/// variant each rule is expected to populate.
#[derive(Debug, Deserialize)]
pub struct RuleProse {
    pub severity_rationale: String,
    #[serde(default)]
    pub likely_cause: Option<String>,
    #[serde(default)]
    pub likely_cause_template: Option<String>,
    #[serde(default)]
    pub likely_cause_template_with_field: Option<String>,
    #[serde(default)]
    pub likely_cause_template_no_field: Option<String>,
    pub hypotheses: Vec<String>,
    pub unknowns: Vec<String>,
    pub next_steps: Vec<String>,
    pub escalation_note: String,
}

impl Prose {
    pub fn rule(&self, name: &str) -> &RuleProse {
        self.rules
            .get(name)
            .unwrap_or_else(|| panic!("missing prose entry for rule `{name}` in prose.toml"))
    }
}

impl RuleProse {
    /// Static likely-cause text for rules that don't interpolate fields.
    pub fn likely_cause_static(&self) -> &str {
        self.likely_cause.as_deref().unwrap_or_else(|| {
            panic!(
                "rule prose has no static `likely_cause`; \
                 use a `likely_cause_template*` accessor instead"
            )
        })
    }

    /// Likely-cause text with `{host}` substituted.
    pub fn likely_cause_with_host(&self, host: &str) -> String {
        self.likely_cause_template
            .as_deref()
            .unwrap_or_else(|| panic!("rule prose has no `likely_cause_template`"))
            .replace("{host}", host)
    }

    /// Likely-cause text with `{peer}` substituted.
    pub fn likely_cause_with_peer(&self, peer: &str) -> String {
        self.likely_cause_template
            .as_deref()
            .unwrap_or_else(|| panic!("rule prose has no `likely_cause_template`"))
            .replace("{peer}", peer)
    }

    /// Likely-cause text for `bad_payload`-style rules where the validated
    /// field may or may not be present. Picks the right template and
    /// substitutes `{field}` when applicable.
    pub fn likely_cause_with_optional_field(&self, field: Option<&str>) -> String {
        match field {
            Some(f) => self
                .likely_cause_template_with_field
                .as_deref()
                .unwrap_or_else(|| panic!("rule prose has no `likely_cause_template_with_field`"))
                .replace("{field}", f),
            None => self
                .likely_cause_template_no_field
                .as_deref()
                .unwrap_or_else(|| panic!("rule prose has no `likely_cause_template_no_field`"))
                .to_string(),
        }
    }
}

/// Access the parsed prose. Loaded and validated once on first call.
pub fn prose() -> &'static Prose {
    static CACHE: OnceLock<Prose> = OnceLock::new();
    CACHE.get_or_init(|| {
        toml::from_str(PROSE_TOML).unwrap_or_else(|e| panic!("prose.toml is malformed: {e}"))
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn prose_parses() {
        // Side effect: panics if the embedded TOML is invalid.
        let _ = prose();
    }

    /// Every likely-cause template variant a rule arm can call.
    ///
    /// This enum exists only inside the test below; it pairs each
    /// `RuleProse` accessor with the rule arms that use it, so the test
    /// can assert that the prose entry actually populates the right
    /// template fields.
    enum TemplateKind {
        Static,
        Host,
        Peer,
        OptionalField,
    }

    /// Source of truth for the rule-name ↔ template-kind binding.
    /// Mirrors the call sites in `diagnose.rs`. If a rule arm starts
    /// calling a different accessor (e.g. switches from `static` to
    /// `with_host`), the binding here must change to match — and the
    /// test below will catch a missing template field at test time
    /// rather than at first runtime call.
    const TEMPLATE_BINDINGS: &[(&str, TemplateKind)] = &[
        ("dns_failure", TemplateKind::Host),
        ("tls_failure", TemplateKind::Peer),
        ("connection_timeout", TemplateKind::Static),
        ("webhook_signature", TemplateKind::Static),
        ("rate_limit", TemplateKind::Static),
        ("auth_missing", TemplateKind::Static),
        ("bad_payload", TemplateKind::OptionalField),
        ("unknown", TemplateKind::Static),
    ];

    #[test]
    fn every_rule_named_in_diagnose_has_prose() {
        let p = prose();
        for (rule, _) in TEMPLATE_BINDINGS {
            // Triggers the panic in `Prose::rule` if missing.
            let _ = p.rule(rule);
        }
    }

    /// Exercise every rule's likely-cause accessor in the same shape its
    /// call site uses. Closes the gap that
    /// `every_rule_named_in_diagnose_has_prose` leaves: a rule whose
    /// `prose.toml` entry has, say, `likely_cause` set when the call
    /// site asks for `likely_cause_template_with_field` would still pass
    /// the presence test but panic at first runtime call. This test
    /// surfaces that mismatch as a test failure instead.
    ///
    /// The placeholder values fed in here (`example.test`,
    /// `field_name`) are chosen to be obviously fake; we only care that
    /// the accessor returns a non-empty string, not that the rendered
    /// prose makes sense.
    #[test]
    fn every_rule_template_kind_matches_its_call_site() {
        let p = prose();
        for (rule, kind) in TEMPLATE_BINDINGS {
            let entry = p.rule(rule);
            let rendered = match kind {
                TemplateKind::Static => entry.likely_cause_static().to_string(),
                TemplateKind::Host => entry.likely_cause_with_host("example.test"),
                TemplateKind::Peer => entry.likely_cause_with_peer("example.test"),
                TemplateKind::OptionalField => {
                    let with = entry.likely_cause_with_optional_field(Some("field_name"));
                    let without = entry.likely_cause_with_optional_field(None);
                    assert!(!with.is_empty(), "{rule}: with-field template empty");
                    assert!(!without.is_empty(), "{rule}: no-field template empty");
                    with
                }
            };
            assert!(!rendered.is_empty(), "{rule}: rendered likely_cause empty");
        }
    }
}
