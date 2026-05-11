//! Snapshot tests pinning the full rendered report for every known case.
//!
//! These tests exist so that any change to a rule, fixture, or renderer that
//! perturbs user-visible output forces an explicit `cargo insta review` step,
//! rather than silently drifting.

#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use llm_assisted_api_debugging_lab::cases::{load_case, log_path_for, KNOWN_CASES};
use llm_assisted_api_debugging_lab::{collect_evidence, diagnose, render_report};
use std::path::PathBuf;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .expect("crate root resolves")
}

fn fixtures_dir() -> PathBuf {
    project_root().join("fixtures")
}

#[test]
fn snapshot_reports_for_all_known_cases() {
    for name in KNOWN_CASES {
        let case =
            load_case(&fixtures_dir(), name).unwrap_or_else(|e| panic!("loading case {name}: {e}"));
        let log_path = log_path_for(&case, &project_root())
            .unwrap_or_else(|| panic!("case {name} missing log_path"));
        let log_text = std::fs::read_to_string(&log_path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", log_path.display()));
        let evidence = collect_evidence(&case, &log_text);
        let diagnosis = diagnose(name, &evidence);
        let rendered = render_report(&diagnosis);

        insta::with_settings!({ snapshot_suffix => *name }, {
            insta::assert_snapshot!("report", rendered);
        });
    }
}
