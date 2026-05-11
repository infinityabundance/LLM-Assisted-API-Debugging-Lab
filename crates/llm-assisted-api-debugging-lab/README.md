# llm-assisted-api-debugging-lab

Deterministic API failure diagnoser with an LLM-assisted prompt template
generator.

This crate is a small support-engineering lab over synthetic fixtures. It
classifies included API failure cases with hand-written Rust rules, renders
evidence-first reports, and emits LLM prompt templates for drafting
customer-facing or escalation communication.

It does not call an LLM, does not use a learned classifier, and does not
claim accuracy outside the included fixtures.

## Quick Start

```bash
cargo run -p llm-assisted-api-debugging-lab -- list-cases
cargo run -p llm-assisted-api-debugging-lab -- diagnose webhook_signature \
  --fixtures-dir crates/llm-assisted-api-debugging-lab/fixtures
cargo run -p llm-assisted-api-debugging-lab -- prompt-json webhook_signature \
  --fixtures-dir crates/llm-assisted-api-debugging-lab/fixtures
```

When running from the crate package root, `--fixtures-dir fixtures` is enough.

The repository contains the full lab, docs, CI workflow, and Colab notebook:
<https://github.com/infinityabundance/LLM-Assisted-API-Debugging-Lab>.
