//! Property-based tests on the rules engine.
//!
//! The unit tests in `diagnose.rs` show that each rule fires when its
//! trigger evidence is present, in the order I happened to think of. The
//! property tests below promote that to a stronger invariant: rule
//! selection depends only on which `Evidence` variants are present, not on
//! the order they appear in the input vector. If a future change introduces
//! an order-sensitive predicate (e.g. an `iter().enumerate()` that happens
//! to look at index), proptest will find it.

#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use llm_assisted_api_debugging_lab::{diagnose, Evidence};
use proptest::prelude::*;

/// A small fixed catalogue of `Evidence` values, one per variant. The
/// property under test is about which rule fires; the field values inside
/// each variant don't matter for that, so we use simple literals.
fn evidence_strategy() -> impl Strategy<Value = Evidence> {
    prop_oneof![
        Just(Evidence::HttpStatus(401)),
        Just(Evidence::HttpStatus(429)),
        Just(Evidence::HttpStatus(400)),
        Just(Evidence::HttpStatus(504)),
        Just(Evidence::SignatureMismatch),
        Just(Evidence::BodyMutatedBeforeVerification),
        Just(Evidence::RetryAfterSecs(12)),
        Just(Evidence::ClockDriftSecs {
            observed: 360,
            tolerance_secs: 300,
        }),
        Just(Evidence::RateLimitObserved {
            observed_rps: 120,
            limit_rps: 100,
        }),
        Just(Evidence::DnsResolutionFailed {
            host: "x.example".into(),
            message: "no such host".into(),
        }),
        Just(Evidence::TlsHandshakeFailed {
            peer: "x.example".into(),
            reason: "certificate has expired".into(),
        }),
        Just(Evidence::ConnectionTimeout {
            elapsed_ms: 5012,
            timeout_ms: 5000,
        }),
        Just(Evidence::JsonValidationError {
            field: Some("amount".into()),
            message: "validation failed".into(),
        }),
        Just(Evidence::HeaderMissing {
            name: "Authorization".into(),
        }),
        Just(Evidence::HeaderPresent {
            name: "Authorization".into(),
            value: Some("***".into()),
        }),
    ]
}

fn evidence_vec_strategy() -> impl Strategy<Value = Vec<Evidence>> {
    prop::collection::vec(evidence_strategy(), 0..16)
}

proptest! {
    /// Reversing the evidence vector must not change which rule fires.
    /// If it does, the rule body looked at order rather than presence,
    /// which would make the diagnoser dependent on log line ordering and
    /// therefore unreproducible across log captures.
    #[test]
    fn rule_selection_is_reverse_invariant(evs in evidence_vec_strategy()) {
        let mut reversed = evs.clone();
        reversed.reverse();
        let d1 = diagnose("test", &evs);
        let d2 = diagnose("test", &reversed);
        prop_assert_eq!(d1.rule, d2.rule, "reversing evidence changed rule selection");
        prop_assert_eq!(
            d1.severity,
            d2.severity,
            "reversing evidence changed severity"
        );
    }

    /// A stronger invariant: rule selection is permutation-invariant for
    /// any rotation. We test rotation specifically (rather than generating
    /// arbitrary permutations) because rotation is cheap to generate and
    /// covers every starting index in `evs`, which is enough to catch any
    /// "first item wins" bug.
    #[test]
    fn rule_selection_is_rotation_invariant(
        evs in evidence_vec_strategy(),
        offset in 0usize..16,
    ) {
        if evs.is_empty() {
            return Ok(());
        }
        let n = evs.len();
        let mut rotated = Vec::with_capacity(n);
        for i in 0..n {
            rotated.push(evs[(i + offset) % n].clone());
        }
        let d1 = diagnose("test", &evs);
        let d2 = diagnose("test", &rotated);
        prop_assert_eq!(d1.rule, d2.rule, "rotating evidence by {} changed rule selection", offset);
    }

    /// Adding a duplicate evidence item must not change which rule fires.
    /// The dedup logic in collect_evidence handles cross-source duplication;
    /// the rules engine must be robust to within-input duplication too.
    #[test]
    fn rule_selection_is_idempotent_under_duplication(
        evs in evidence_vec_strategy(),
        dup_index in 0usize..16,
    ) {
        if evs.is_empty() {
            return Ok(());
        }
        let mut duped = evs.clone();
        let pick = dup_index % evs.len();
        duped.push(evs[pick].clone());
        let d1 = diagnose("test", &evs);
        let d2 = diagnose("test", &duped);
        prop_assert_eq!(d1.rule, d2.rule, "duplicating evidence changed rule selection");
    }
}
