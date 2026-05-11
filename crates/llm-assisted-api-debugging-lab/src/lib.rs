//! Library entrypoint.
//!
//! ## Layering
//!
//! ```text
//! Case + log  ->  Vec<Evidence>  ->  Diagnosis  -+->  Report (human)
//!                                                |->  Prompt (LLM)
//!                                                +->  Prompt JSON (LLM)
//! ```
//!
//! 1. [`cases`] loads a [`Case`] (a sanitized HTTP transaction) from a
//!    fixture file.
//! 2. [`evidence::collect_evidence`] normalizes the case and its matching
//!    log file into a `Vec<Evidence>`. The log parser ([`evidence::parse_log`])
//!    is also exposed so the `diagnose-log` subcommand can run against a
//!    bare log without a JSON fixture.
//! 3. [`diagnose::diagnose`] is a **pure** function over `(name, &[Evidence])`
//!    that produces a [`Diagnosis`]. There is no clock, no env, no fs, no
//!    randomness inside the rules — every snapshot test is reproducible
//!    on any machine.
//! 4. The renderers ([`render_report`], [`render_short`], [`render_prompt`],
//!    [`render_prompt_json`]) each consume a `&Diagnosis` and produce
//!    user-visible output. None of them can reach back into the raw
//!    `Case`. This is the architectural guarantee that the LLM-facing
//!    surface cannot influence diagnostic truth.
//!
//! ## Re-exports
//!
//! Every public item a downstream caller needs is re-exported from the
//! crate root, so `use llm_assisted_api_debugging_lab::diagnose;` works without naming the
//! module. The modules themselves remain `pub` for callers who want to
//! reach internal helpers (e.g. [`report::render_evidence`] used by the
//! tests).

pub mod cases;
pub mod diagnose;
pub mod evidence;
pub mod llm_prompt;
pub mod prose;
pub mod report;

pub use cases::{Case, CaseError, KNOWN_CASES};
pub use diagnose::{diagnose, Diagnosis, Severity, SeveritySource};
pub use evidence::{collect_evidence, parse_log, Evidence};
pub use llm_prompt::{render_prompt, render_prompt_json};
pub use report::{render_report, render_short};
