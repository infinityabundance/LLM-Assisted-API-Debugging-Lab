# LLM-assisted workflow

## What this layer does

There are two prompt renderers, intended for different model APIs:

- `render_prompt(diagnosis) -> String` — prose prompt, suitable for chat-style
  completion APIs.
- `render_prompt_json(diagnosis) -> serde_json::Value` — structured envelope
  with the same content, suitable for typed-output / JSON-mode APIs. Removes
  a class of "the model rewrote my section heading" failures.

Both go through the same sanitizer at the boundary. Both consume only
`Diagnosis`, never raw case data.

The prose variant produces a prompt that:

1. Tells the model its job is to write communication, not to classify.
2. Reproduces the case name, severity, and likely cause as already assigned by
   the deterministic rules engine.
3. Lists the observed evidence under an `EVIDENCE` heading and instructs the
   model not to contradict or extend it.
4. Lists the consistent-but-unverified reasoning under a `HYPOTHESES` heading
   and instructs the model not to assert any of them as fact.
5. Lists the genuinely unknown questions under an `UNKNOWNS` heading and
   instructs the model not to invent answers.
6. Asks for two outputs: a short customer reply and an internal escalation
   note that separates evidence from hypothesis and marks unknowns.

## What this layer deliberately does not do

- **No network calls.** The binary never opens a socket to any model
  provider. There is no API client, no API key plumbing, no model adapter.
  The `prompt` subcommand only emits text.
- **No access to raw case data.** Both `render_prompt` and
  `render_prompt_json` consume a `Diagnosis`. Neither can read the original
  `Case` JSON or log file. This is the architectural guarantee that the
  LLM-facing surface cannot influence diagnostic truth.
- **No claim of model accuracy.** The lab makes no statement about how well
  any specific model handles the prompt. The prompt is the input under our
  control; output quality is a property of the model the user chooses to send
  it to.

## Threat model: what the prompt layer does and does not protect against

The "LLM-facing layer cannot influence diagnostic truth" claim is precise. It
covers the **control path**: `render_prompt` consumes only `Diagnosis`, so a
prompt cannot reach back into `diagnose()` and change a classification. The
type system enforces this.

It does **not** cover the **content path** by itself. Free-text fields
sourced from log lines and HTTP response bodies (e.g. an error `message`,
a DNS host string) flow into the rendered prompt as evidence text. Without
treatment, hostile content in those fields could attempt prompt injection.

The lab handles this with two mitigations:

1. **Sanitization at the prompt boundary.** Both `render_prompt` and
   `render_prompt_json` run every free-text evidence value through the same
   `sanitize_for_prompt` step that strips control characters, replaces
   newlines with literal `\n`, escapes backticks, and caps the displayed
   length (the trailing `…` is included in the cap). The
   `injection_attempt` fixture and its matching snapshots in both renderer
   families exercise this with a hostile DNS error string; any regression
   in the sanitizer would fail `cargo test`.
2. **Explicit framing in the prompt itself.** The EVIDENCE block is
   labeled as untrusted observations, not as instructions, and a CONSTRAINTS
   block tells the model to phrase observations as "our verifier reports
   X" rather than as assertions about the customer's stack.

These mitigations reduce the surface; they do not eliminate it. **The
lab does not protect against:**

- A model fabricating evidence anyway. The prompt forbids it; the model
  may still do it. Operationally, treat outputs as drafts.
- A model producing partial output, refusing the task, or returning the
  prompt verbatim. The lab has no model and so cannot mitigate this; the
  caller must.
- A model contradicting evidence. The prompt forbids this in text; in
  practice, defense is by review.
- A clever injection that survives sanitization (e.g. base64-encoded
  instructions inside an evidence string). Sanitization is structural, not
  semantic. The right defense is human review of model output before it
  reaches a customer, which the suggested usage flow already requires.

If you wire this prompt to a real model, do not skip the human-review step
at the end of "Suggested usage."

## Why this shape

Two failure modes are common when LLMs are wired into support workflows:

1. **The model invents evidence.** Asked to explain a 401, it confidently
   names a header that wasn't actually missing.
2. **The model collapses the distinction between fact and hypothesis.** The
   customer reply reads as a diagnosis even when the data only supports
   speculation.

The Evidence / Hypotheses / Unknowns split is a direct counter to both. The
prompt explicitly forbids contradicting evidence and explicitly forbids
asserting hypotheses as fact. The structure is also legible to a human
reviewer: a support engineer can read the prompt and see exactly what the
model was given, what it was told it could and could not say, and what the
escalation note should look like.

## Suggested usage

The intended human workflow is:

1. Run `report <case>` to read the deterministic diagnosis yourself.
2. Decide whether the rules-engine output is the right cause. If not, fix the
   rule before going further; do not paper over a wrong rule with prompt
   wording.
3. Run `prompt <case>` and feed the prompt to whatever model your team is
   already approved to use. (Outside the scope of this lab.)
4. Treat the model's customer reply and escalation note as drafts. The
   support engineer remains accountable.

## What would change if we wired a model in

If this lab grew a `complete <case>` subcommand that actually called a model,
the constraints would be:

- The model would receive only the rendered prompt, not the raw `Case`.
- Responses would be stored verbatim alongside the prompt for audit.
- A regression suite would compare model responses to a small set of
  hand-graded reference outputs. We would not silently accept "looks fine."
- The deterministic diagnosis would still ship as the source of truth in
  every output, with the model's text labeled as a draft to be reviewed.

These constraints are not implemented here, by design - their absence keeps
this lab small enough to read in one sitting.
