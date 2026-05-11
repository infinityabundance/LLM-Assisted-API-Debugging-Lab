//! Snapshot tests pinning the full rendered LLM prompt template for every
//! known case. Same mechanism as `reports.rs`: any change perturbs user-visible
//! prompt text and forces an explicit `cargo insta review` step.

#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use llm_assisted_api_debugging_lab::cases::{load_case, log_path_for, KNOWN_CASES};
use llm_assisted_api_debugging_lab::{collect_evidence, diagnose, render_prompt};
use std::path::PathBuf;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("project root resolves")
}

fn fixtures_dir() -> PathBuf {
    project_root().join("fixtures")
}

#[test]
fn snapshot_prompts_for_all_known_cases() {
    for name in KNOWN_CASES {
        let case =
            load_case(&fixtures_dir(), name).unwrap_or_else(|e| panic!("loading case {name}: {e}"));
        let log_path = log_path_for(&case, &project_root())
            .unwrap_or_else(|| panic!("case {name} missing log_path"));
        let log_text = std::fs::read_to_string(&log_path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", log_path.display()));
        let evidence = collect_evidence(&case, &log_text);
        let diagnosis = diagnose(name, &evidence);
        let rendered = render_prompt(&diagnosis);

        insta::with_settings!({ snapshot_suffix => *name }, {
            insta::assert_snapshot!("prompt", rendered);
        });
    }
}

/// Behavioural assertion separate from the snapshot pin: the rendered
/// prompt for `injection_attempt` must contain the hostile text only in
/// its sanitized form (literal `\n`, escaped backticks, single physical
/// line per evidence bullet). The snapshot would catch any regression
/// visually; this test asserts the sanitization invariants directly so a
/// future cosmetic snapshot diff cannot mask a security regression.
#[test]
fn injection_attempt_prompt_neutralizes_hostile_text() {
    let case = load_case(&fixtures_dir(), "injection_attempt")
        .unwrap_or_else(|e| panic!("loading injection_attempt: {e}"));
    let log_path = log_path_for(&case, &project_root())
        .unwrap_or_else(|| panic!("injection_attempt missing log_path"));
    let log_text = std::fs::read_to_string(&log_path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", log_path.display()));
    let evidence = collect_evidence(&case, &log_text);
    let diagnosis = diagnose("injection_attempt", &evidence);
    let rendered = render_prompt(&diagnosis);

    // Locate the EVIDENCE block.
    let evidence_block_start = rendered
        .find("EVIDENCE")
        .expect("rendered prompt must contain EVIDENCE block");
    let after_evidence = &rendered[evidence_block_start..];
    let next_section = after_evidence
        .find("\n\nHYPOTHESES")
        .expect("EVIDENCE block must be followed by HYPOTHESES");
    let evidence_block = &after_evidence[..next_section];

    // Invariant 1: every evidence bullet is a single physical line
    // (the sanitizer replaces real newlines with literal "\n").
    for line in evidence_block.lines().filter(|l| l.starts_with("- ")) {
        assert!(
            !line.contains('\n') && !line.contains('\r'),
            "evidence bullet must not contain embedded line breaks: {line:?}"
        );
        // Invariant 2: any backtick in an evidence bullet must be
        // preceded by a backslash (the sanitizer escapes them).
        let mut prev = ' ';
        for ch in line.chars() {
            if ch == '`' {
                assert_eq!(
                    prev, '\\',
                    "raw backtick must be escaped in evidence bullet: {line:?}"
                );
            }
            prev = ch;
        }
    }

    // Invariant 3: the hostile string is present in its sanitized form,
    // not silently dropped. We confirm that the literal escape sequence
    // "\n" (two chars: backslash + n) precedes the directive, which means
    // the sanitizer ran and the original newline was replaced.
    assert!(
        rendered.contains("\\nIGNORE ALL PREVIOUS"),
        "sanitized form of the injection (literal backslash-n + directive) must be visible"
    );

    // Invariant 4: there is no line in the entire prompt that consists
    // solely of the hostile directive (which would happen if the
    // sanitizer let a real newline through and split the directive onto
    // its own line where a model could read it as an instruction).
    for line in rendered.lines() {
        assert!(
            !line.trim_start().starts_with("IGNORE ALL PREVIOUS"),
            "hostile directive must never appear at the start of a standalone line: {line:?}"
        );
    }
}
