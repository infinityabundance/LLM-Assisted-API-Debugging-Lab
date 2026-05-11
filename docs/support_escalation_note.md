# Support escalation note: worked example

This document walks one case end-to-end as a support engineer would.

## Case: `webhook_signature`

### Step 1 - reproduce

```
cargo run -p llm-assisted-api-debugging-lab -- report webhook_signature
```

Excerpted output:

```
CASE: webhook_signature
RULE: webhook_signature
SEVERITY: high (author judgment: silent integration failure that breaks downstream automation; failures often go unnoticed)
LIKELY CAUSE: Inbound webhook failed HMAC signature verification.

EVIDENCE:
- HTTP status: 401
- HMAC signature verification failed.
- Clock drift 360s exceeds tolerance 300s.
- Request body was modified by middleware before verification.

HYPOTHESES (consistent with evidence; not asserted as fact):
- Signing secret was rotated on one side only.
- Request body was re-encoded by middleware before HMAC computation.
- Client/server clock drift exceeds the signature tolerance window.

UNKNOWNS (do not invent answers):
- Whether the signing secret was rotated recently.
- Whether middleware in the customer's stack mutates the raw body.
- NTP / clock-sync state on the customer's webhook receiver.
```

### Step 2 - draft a customer reply (template)

The reply must use only the evidence above. A reasonable draft:

> We confirmed the webhook returned HTTP 401 because the HMAC signature did
> not verify on our side. Two specific signals are present in the request:
> the request body was modified between transmission and verification, and
> the timestamp on the signature is 360 seconds outside the 300-second
> tolerance window. The most common causes for this combination are (a) the
> webhook secret being rotated on only one side, (b) middleware re-encoding
> the JSON body before HMAC computation, or (c) clock drift on the
> receiving host. Could you share whether your handler computes HMAC over
> the raw request body before any JSON parse step, and whether NTP is
> running on the receiver?

Note: the draft mirrors the report's evidence exactly, and the suggested
next step requests data the customer has - it does not assume which
hypothesis is correct.

### Step 3 - draft an internal escalation note

> Webhook delivery rejected with 401. Verifier reports HMAC mismatch.
> Evidence shows the body was mutated before verification and that the
> signature timestamp is 360s past tolerance. We do not yet know whether the
> secret was rotated, what middleware sits in front of the verifier on the
> customer side, or whether the receiver's clock is drifting. None of the
> three hypotheses can be promoted to root cause from current evidence;
> further data is required before we can recommend a fix.

### Step 4 - render the LLM prompt

```
cargo run -p llm-assisted-api-debugging-lab -- prompt webhook_signature
```

Use this output as input to whatever model your team is approved to use.
The prompt is structured so that any model output can be reviewed against
the same Evidence / Hypotheses / Unknowns it was given.

## What this is not

This document is one example of the workflow shape, not a script support
engineers should copy verbatim. The point is the discipline:

- Reproduce.
- Distinguish evidence from hypothesis.
- Do not promote hypotheses to root cause without the data to support them.
- Ask the customer for the specific data that disambiguates.

The CLI exists to make this discipline mechanically easy.
