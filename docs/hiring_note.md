# Hiring note

A one-page factual summary of what this repository contains, what it does
not claim, and how to verify it in five minutes.

This artifact is positioned for **Developer Support / Technical Escalation
Engineering** roles. It is not pitched as a generalist Rust portfolio piece
or as an AI-backend portfolio piece — it has no concurrency, no networking,
no perf work, and no model integration. What it demonstrates is the
support-engineering reflex of separating evidence from hypothesis, expressed
in Rust that holds up to a code review.

## What is in this repo

- A Rust workspace with one library + binary crate (`llm-assisted-api-debugging-lab`).
- Eight request/response JSON fixtures plus eight matching structured log
  files under `fixtures/`. Each fixture is a sanitized HTTP transaction
  with ISO-8601 timestamps, masked tokens, and a `request_id` that threads
  through the log file. One fixture (`injection_attempt`) deliberately
  carries hostile prompt-injection text in its log to exercise the prompt
  layer's sanitization.
- A deterministic rules engine in `crates/llm-assisted-api-debugging-lab/src/diagnose.rs`.
  Each rule is its own function; the rule-specific bits (trigger pattern,
  severity, pinned evidence selection, likely-cause computation) live in
  the rule arm, while the `Diagnosis` construction itself goes through a
  shared `from_rule` builder. Each rule has at least one unit test,
  including a fallback that refuses to invent a diagnosis when no rule
  matches.
- Two LLM prompt template renderers in `src/llm_prompt.rs`: a prose form
  (`render_prompt`) and a JSON-envelope form (`render_prompt_json`) for
  typed-output APIs. Both consume only the rules engine's `Diagnosis`
  output and sanitize free-text fields before rendering. The binary makes
  no network calls.
- A unit-test suite covering the case loader, the log parser (including
  negative cases for phantom evidence and substring boundary collisions),
  every rule arm, the unknown fallback, and the prose↔rule binding
  (`every_rule_template_kind_matches_its_call_site` exercises each rule's
  likely-cause accessor in the same shape its rule arm uses). `insta`
  snapshot tests pin user-visible output across four renderers per case
  (compact summary, full report, prose prompt, JSON-envelope prompt) for
  32 pinned outputs. `proptest` properties pin rule selection as
  permutation-, rotation-, and duplication-invariant.
- A GitHub Actions workflow that runs `cargo fmt --check`, `cargo clippy
  --locked --workspace --all-targets -- -D warnings`, and `cargo test
  --locked --workspace --all-targets` on Ubuntu / pinned Rust.
- A five-minute demo script (`scripts/run_demo.sh`).
- A Colab notebook (`notebooks/llm_assisted_api_debugging_lab_colab.ipynb`)
  that installs Rust, clones the repo from GitHub, and runs the same gates
  from scratch.

## What this repo does not claim

- It does not claim to diagnose anything beyond the included fixtures.
- It does not claim model accuracy. The LLM layer renders prompt text only;
  the binary makes no network calls.
- Severity levels reflect immediacy of failure to the requested transaction,
  not blast radius; this is author judgment, not measured impact. See the
  README's "What it does (and does not) claim" section for the full
  ranking philosophy.
- The fixtures are illustrative, not drawn from any production system.

## How to verify in five minutes

```
cargo test --locked --workspace --all-targets  # all unit + snapshot tests pass
cargo fmt --check
cargo clippy --locked --workspace --all-targets -- -D warnings
./scripts/run_demo.sh                     # exercises every subcommand
```

Reading order for a code review:

1. `crates/llm-assisted-api-debugging-lab/src/diagnose.rs` - the rules.
2. `crates/llm-assisted-api-debugging-lab/src/evidence.rs` - what the rules consume.
3. `crates/llm-assisted-api-debugging-lab/src/llm_prompt.rs` - the prompt design and
   sanitization (both prose and JSON-envelope renderers).
4. `crates/llm-assisted-api-debugging-lab/src/prose.rs` and `prose.toml` at the workspace
   root - the editorial/logic split.
5. `crates/llm-assisted-api-debugging-lab/tests/snapshots/` - what the output actually looks
   like for each case, including the `injection_attempt` snapshot showing
   sanitization in action and the `tls_failure` snapshot showing a single
   well-formed evidence line (no phantom from the abort log).
6. `crates/llm-assisted-api-debugging-lab/tests/proptests.rs` - the rule-selection
   invariants.
7. `docs/architecture.md` for the layering, then
   `docs/llm_assisted_workflow.md` for the threat model the prompt layer
   does and does not address.

## What this repo is meant to demonstrate

- The **support-engineering reflex** of separating evidence from hypothesis,
  marking unknowns explicitly, and refusing to promote a hypothesis to root
  cause without the data to support it.
- Discipline around **determinism in code that feeds an LLM workflow**: the
  rules engine has no clock, env, fs, or randomness, and the LLM-facing
  layer cannot influence diagnostic truth (verified by type signatures,
  not by README assertion).
- A **trust-boundary mindset** at the prompt seam: free-text fields from
  log lines and response bodies are sanitized before they enter the prompt,
  and a dedicated fixture exercises this with hostile content.
- **Idiomatic Rust** in support of all of the above: workspace-scoped
  lints, library/binary split, typed errors via `thiserror` with `anyhow`
  at the binary boundary, `clap` derive, `serde` for fixtures,
  `insta`-pinned user-facing output.
