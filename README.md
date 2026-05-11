# LLM-Assisted API Debugging Lab

A portfolio piece for **Developer Support / Technical Escalation Engineering**:
a small, reproducible lab for classifying API failures the way a careful
support engineer does — evidence first, hypothesis second, attribution last.

It ships eight intentionally-failing API cases (JSON fixtures plus structured
log files) and a Rust CLI that classifies each failure deterministically and
emits a structured prompt template for an LLM to convert into customer-facing
or escalation communication.

The diagnostic layer is deterministic. The LLM-assisted layer renders prompt
text only; the binary makes no network calls.

## What it does (and does not) claim

- **Does:** match the included fixtures against hand-written rules and emit a
  report containing severity, evidence, hypotheses, unknowns, reproduction
  command, ordered next steps, and an escalation note.
- **Does:** render an LLM prompt template that consumes only the diagnosis
  output, with explicit Evidence / Hypotheses / Unknowns sections and
  constraints that forbid inventing facts.
- **Does not:** use a learned model to classify failures. Rules are
  hand-written and pinned by snapshot tests.
- **Does not:** call any LLM. No API keys are required or accepted.
- **Does not:** claim accuracy on traffic outside the included fixtures.
- **Severity** levels are author judgment, not measured impact. The ranking
  reflects the **immediacy of the failure to the requested transaction**
  (connection-fail > silent-misclassification > timeout > rate-limit >
  validation), not the blast radius of the underlying incident. A real
  on-call rotation would weight by blast radius too; the diagnoser has no
  visibility into that.

## Five-minute path

```
cargo test --locked --workspace --all-targets  # 33 lib unit tests + 9 integration tests (incl. 3 proptest properties); 32 snapshot-pinned outputs
cargo run -p llm-assisted-api-debugging-lab -- list-cases
cargo run -p llm-assisted-api-debugging-lab -- diagnose webhook_signature
cargo run -p llm-assisted-api-debugging-lab -- diagnose-log fixtures/logs/timeout.log
cargo run -p llm-assisted-api-debugging-lab -- report rate_limit
cargo run -p llm-assisted-api-debugging-lab -- prompt webhook_signature
cargo run -p llm-assisted-api-debugging-lab -- prompt-json webhook_signature   # JSON envelope
```

Or:

```
./scripts/run_demo.sh
```

## Cases shipped

| Case | Failure mode | Rule | Severity |
|---|---|---|---|
| `auth_missing` | 401 with no Authorization header | `auth_missing` | medium |
| `bad_payload` | 400 with structured validation error | `bad_payload` | low |
| `rate_limit` | 429 with Retry-After and burst log | `rate_limit` | medium |
| `webhook_signature` | 401, HMAC mismatch, body mutated, clock drift | `webhook_signature` | high |
| `timeout` | client-side timeout, no response | `connection_timeout` | high |
| `dns_config` | name resolution failed | `dns_failure` | critical |
| `tls_failure` | TLS handshake failed (expired leaf certificate) | `tls_failure` | critical |
| `injection_attempt` | DNS error message carries hostile prompt-injection text; exercises the prompt-layer sanitizer | `dns_failure` | critical |

## Layering

```
Case + log  ->  Evidence  ->  Diagnosis  ->  Report
                                          \-> LLM prompt
```

`Case` and log lines are normalized into typed `Evidence` items. The rules
engine consumes only `Evidence`, so it is a pure function of its input. The
LLM prompt renderer consumes the `Diagnosis`, never the raw case data, so the
LLM-facing surface cannot influence diagnostic truth. See
[docs/architecture.md](docs/architecture.md).

## Verification

- `cargo test` exercises the rules per case (`crates/llm-assisted-api-debugging-lab/src/diagnose.rs`)
  and pins the rendered output for every case via `insta` snapshots
  (`crates/llm-assisted-api-debugging-lab/tests/snapshots/`).
- `cargo fmt --check` and `cargo clippy --locked --workspace --all-targets -- -D warnings`
  pass on stable Rust.
- The same three commands run in `.github/workflows/ci.yml`.
- Updating a snapshot is a deliberate `cargo insta review` action, not silent
  drift.

## Repository layout

```
crates/llm-assisted-api-debugging-lab/    library + binary
fixtures/cases/          eight request/response JSON fixtures
fixtures/logs/           eight matching structured log files
crates/llm-assisted-api-debugging-lab/prose.toml
                         per-rule editorial content (likely-cause templates,
                         hypotheses, unknowns, next-steps, escalation notes,
                         severity rationales)
docs/                    architecture, LLM workflow, support and hiring notes
notebooks/               Colab notebook that clones and verifies from scratch
scripts/run_demo.sh      five-minute demo runner
.github/workflows/ci.yml fmt + clippy + test
rust-toolchain.toml      pinned Rust toolchain for local/CI/Colab parity
```

## Further reading

- [docs/architecture.md](docs/architecture.md) - the layering, in one page.
- [docs/llm_assisted_workflow.md](docs/llm_assisted_workflow.md) - what the
  prompt layer is and is not.
- [docs/support_escalation_note.md](docs/support_escalation_note.md) - example
  of using the rendered report and prompt in a real support workflow.
- [docs/hiring_note.md](docs/hiring_note.md) - one-page factual summary for
  reviewers.

## License

Apache-2.0. See [LICENSE](LICENSE).
