//! Snapshot tests pinning the compact `diagnose` subcommand summary for
//! every known case. The summary is the most-shown surface of the CLI
//! (it's the first command in `scripts/run_demo.sh`); without these
//! snapshots, a wording or format change would slip through.

#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use llm_assisted_api_debugging_lab::cases::{load_case, log_path_for, KNOWN_CASES};
use llm_assisted_api_debugging_lab::{collect_evidence, diagnose, render_short};
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
fn snapshot_short_summaries_for_all_known_cases() {
    for name in KNOWN_CASES {
        let case =
            load_case(&fixtures_dir(), name).unwrap_or_else(|e| panic!("loading case {name}: {e}"));
        let log_path = log_path_for(&case, &project_root())
            .unwrap_or_else(|| panic!("case {name} missing log_path"));
        let log_text = std::fs::read_to_string(&log_path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", log_path.display()));
        let evidence = collect_evidence(&case, &log_text);
        let diagnosis = diagnose(name, &evidence);
        let rendered = render_short(&diagnosis);

        insta::with_settings!({ snapshot_suffix => *name }, {
            insta::assert_snapshot!("short", rendered);
        });
    }
}
