//! Snapshot tests pinning the JSON-envelope LLM prompt for every known case.
//!
//! Same mechanism as `prompts.rs`: any change to the JSON shape, sanitizer
//! behavior, or constraint wording forces an explicit `cargo insta review`.

#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use llm_assisted_api_debugging_lab::cases::{load_case, log_path_for, KNOWN_CASES};
use llm_assisted_api_debugging_lab::{collect_evidence, diagnose, render_prompt_json};
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
fn snapshot_prompts_json_for_all_known_cases() {
    for name in KNOWN_CASES {
        let case =
            load_case(&fixtures_dir(), name).unwrap_or_else(|e| panic!("loading case {name}: {e}"));
        let log_path = log_path_for(&case, &project_root())
            .unwrap_or_else(|| panic!("case {name} missing log_path"));
        let log_text = std::fs::read_to_string(&log_path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", log_path.display()));
        let evidence = collect_evidence(&case, &log_text);
        let diagnosis = diagnose(name, &evidence);
        let value = render_prompt_json(&diagnosis);
        let rendered = serde_json::to_string_pretty(&value)
            .unwrap_or_else(|e| panic!("serializing prompt-json for {name}: {e}"));

        insta::with_settings!({ snapshot_suffix => *name }, {
            insta::assert_snapshot!("prompt_json", rendered);
        });
    }
}

/// Behavioural assertion mirroring the prose-prompt injection test:
/// the JSON envelope's `evidence` array must contain the hostile string
/// only in its sanitized form (literal `\n`, escaped backticks, single
/// physical line per element).
#[test]
fn injection_attempt_prompt_json_neutralizes_hostile_text() {
    let case = load_case(&fixtures_dir(), "injection_attempt")
        .unwrap_or_else(|e| panic!("loading injection_attempt: {e}"));
    let log_path = log_path_for(&case, &project_root())
        .unwrap_or_else(|| panic!("injection_attempt missing log_path"));
    let log_text = std::fs::read_to_string(&log_path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", log_path.display()));
    let evidence = collect_evidence(&case, &log_text);
    let diagnosis = diagnose("injection_attempt", &evidence);
    let value = render_prompt_json(&diagnosis);

    let evidence_array = value
        .get("evidence")
        .and_then(|v| v.as_array())
        .expect("evidence must be a JSON array");

    let mut saw_sanitized = false;
    for item in evidence_array {
        let s = item.as_str().expect("evidence items must be strings");
        // No real newlines in any evidence string.
        assert!(
            !s.contains('\n') && !s.contains('\r'),
            "evidence string must not contain embedded line breaks: {s:?}"
        );
        // Backticks must be escaped.
        let mut prev = ' ';
        for ch in s.chars() {
            if ch == '`' {
                assert_eq!(
                    prev, '\\',
                    "raw backtick must be escaped in evidence string: {s:?}"
                );
            }
            prev = ch;
        }
        if s.contains("\\nIGNORE ALL PREVIOUS") {
            saw_sanitized = true;
        }
    }
    assert!(
        saw_sanitized,
        "sanitized form of the injection (literal backslash-n + directive) must appear in evidence array"
    );
}
