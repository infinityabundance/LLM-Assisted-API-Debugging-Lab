# Architecture

## Layering

```
Case JSON + log file
        |
        v   collect_evidence(case, log)
   Vec<Evidence>
        |
        v   diagnose(name, evidence)        <-- pure rules, no I/O
     Diagnosis    <-- prose loaded from prose.toml at the crate root
        |
        +--> render_report(diagnosis)         human report
        |
        +--> render_short(diagnosis)          compact CLI summary
        |
        +--> render_prompt(diagnosis)         prose LLM prompt
        |
        +--> render_prompt_json(diagnosis)    JSON-envelope LLM prompt
```

Editorial separation: rule logic lives in `crates/llm-assisted-api-debugging-lab/src/diagnose.rs`,
prose lives in `crates/llm-assisted-api-debugging-lab/prose.toml`. Wording changes (a clearer hypothesis, a tighter
escalation note) do not require a code change. Rule logic changes (severity,
rule order, evidence patterns) still go in `diagnose.rs`.

Three properties are deliberately preserved by this shape:

1. **The rules engine is pure.** `diagnose()` reads only `Evidence`. There is
   no clock, env, fs, or randomness inside the rules. This is what makes the
   snapshot tests deterministic on any machine.

2. **The LLM-facing layer cannot affect truth.** `render_prompt` consumes a
   `Diagnosis` and never sees the raw `Case`. If the rules don't classify a
   failure, the prompt cannot retroactively classify it either; it can only
   produce communication around what was already concluded.

3. **Evidence is the only currency.** Cases and log lines are normalized into
   typed `Evidence` variants in `evidence.rs`. Adding a new failure mode is a
   matter of (a) extending `Evidence` if a new signal is needed, (b) adding a
   rule arm in `diagnose.rs`, and (c) writing a fixture pair plus a unit test.

## Modules

| Module | Responsibility |
|---|---|
| `cases.rs` | `Case` struct, JSON loader, `KNOWN_CASES` list. |
| `evidence.rs` | `Evidence` enum, `collect_evidence`, `parse_log`. |
| `diagnose.rs` | Rules engine. Each rule is its own function returning `Option<Diagnosis>`; the rule-specific bits (trigger, severity, pinned evidence, likely-cause computation) live in the rule arm, while the `Diagnosis` construction itself goes through the `from_rule` builder so every rule produces the same shape. |
| `report.rs` | `Diagnosis -> String` (human report) plus `render_short` for the compact diagnose summary. |
| `llm_prompt.rs` | `Diagnosis -> String` (prose prompt template) plus `Diagnosis -> serde_json::Value` (JSON envelope) and the boundary sanitizer. |
| `prose.rs` | Loads per-rule prose (likely-cause templates, hypotheses, unknowns, next-steps, escalation note, severity rationale) from `prose.toml` at the crate root via `include_str!` + `OnceLock`. |
| `main.rs` | clap CLI, dispatches to library functions. Exit codes: 0 success, 2 unknown case, 3 malformed fixture. |

## Log marker grammar

`parse_log` is substring-based. The markers it recognizes:

| Marker (substring or `key=value`) | Evidence emitted |
|---|---|
| `reason=signature_mismatch` or `signature verification failed` | `SignatureMismatch` |
| `body_modified=true` or `body_mutated=true` | `BodyMutatedBeforeVerification` |
| `drift_secs=N tolerance_secs=M` | `ClockDriftSecs { observed: \|N\|, tolerance_secs: M }` |
| `schema validation failed` (with optional `field=...`) | `JsonValidationError` |
| `burst above limit` (with `retry_after_secs=N`, `observed_rps=X`, `limit_rps=Y`) | `RetryAfterSecs(N)`, `RateLimitObserved` |
| `name resolution failed` **with required `host=...`** (and optional `error=...`) | `DnsResolutionFailed` |
| `tls handshake failed` **with required `peer=...`** (and optional `error=...`) | `TlsHandshakeFailed` |
| `upstream timeout` (with `elapsed_ms=...`, `timeout_ms=...`) | `ConnectionTimeout` |

The `host=` / `peer=` fields are required, not just suggested: a log line that
mentions the marker substring as descriptive prose (e.g.
`msg="aborting request: tls handshake failed"`) without an identifier is
*not* a fresh observation, and emitting a `<unknown peer>` placeholder there
would create a phantom evidence line that the dedup logic cannot collapse
against the real one. The tests
`parse_log_does_not_emit_phantom_tls_for_abort_line` and
`parse_log_does_not_emit_phantom_dns_for_abort_line` pin this behavior.

Adding a marker is a one-line change.

## Rule order

Rules are tried in this fixed order. The first match wins:

1. `dns_failure` - fires on `DnsResolutionFailed`.
2. `tls_failure` - fires on `TlsHandshakeFailed`.
3. `connection_timeout` - fires on `ConnectionTimeout`.
4. `webhook_signature` - fires on `SignatureMismatch`.
5. `rate_limit` - fires on `HttpStatus(429) AND RetryAfterSecs`.
6. `auth_missing` - fires on `HttpStatus(401) AND HeaderMissing("Authorization")`.
7. `bad_payload` - fires on `HttpStatus(400) AND JsonValidationError`.
8. `unknown` - fallback. Reports evidence and explicitly does not assign a cause.

The ordering is from most specific (network-layer failure) to least specific
(application-layer failure). This matters for cases where multiple rules
could in principle match: for example, a DNS failure fixture also lacks
HTTP status evidence, so `auth_missing` cannot fire even if `Authorization`
is missing - but `dns_failure` is checked first regardless.

## Why insta

Snapshot tests are how this lab enforces output stability. Snapshots live
under `crates/llm-assisted-api-debugging-lab/tests/snapshots/`, one per case per renderer:
report, short summary, prose prompt, and JSON-envelope prompt — four
families covering every user-visible surface. Any change to a rule,
fixture, or renderer that perturbs output requires a deliberate
`cargo insta review` step. Silent output drift is not possible.

## Why proptest

The unit tests in `diagnose.rs` show that each rule fires when its trigger
evidence is present. The property tests in
`crates/llm-assisted-api-debugging-lab/tests/proptests.rs` promote that to a stronger
invariant: rule selection depends only on **which** `Evidence` variants are
present, not on the order they appear in the input vector. Three properties
hold across 256 random inputs each (768 hidden assertions per test run):

- `rule_selection_is_reverse_invariant` — reversing the input does not
  change the rule selected.
- `rule_selection_is_rotation_invariant` — rotating the input by any
  offset does not change the rule selected.
- `rule_selection_is_idempotent_under_duplication` — adding a duplicate
  evidence item does not change the rule selected.

If a future change introduces an order-sensitive predicate (e.g. an
`iter().enumerate()` that happens to look at index), proptest will find
it before snapshot review does.

## Prose / rule-arm consistency

`prose.rs` ships two unit tests that together pin the binding between
rule arms in `diagnose.rs` and per-rule entries in `prose.toml`:

- `every_rule_named_in_diagnose_has_prose` — every rule name listed in
  `TEMPLATE_BINDINGS` has a section in `prose.toml`.
- `every_rule_template_kind_matches_its_call_site` — exercises each
  rule's likely-cause accessor in the same shape its rule arm uses
  (static, with-host, with-peer, with-optional-field). Catches a
  mismatch (e.g. a rule arm that calls `likely_cause_with_host` against
  a prose entry that only has a static `likely_cause`) at test time
  rather than at first runtime call.

`TEMPLATE_BINDINGS` in `prose.rs` is the single source of truth for the
binding. Adding a new rule means adding a row there *and* a section in
`prose.toml`; both tests will fail if either is missing.
