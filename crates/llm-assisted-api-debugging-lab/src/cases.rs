//! Case fixture model and JSON loader.
//!
//! A [`Case`] is a sanitized HTTP transaction plus environmental
//! [`Context`]. Each variant the diagnoser cares about lives as an
//! explicit field — the struct is **not** a generic `serde_json::Value`
//! bag, because we want serde to fail loudly when a fixture changes shape
//! in a way the code didn't expect.
//!
//! Loading is gated on two checks (in order):
//! 1. The requested name is in [`KNOWN_CASES`] — see [`case_fixture_path`].
//! 2. The loaded JSON's `name` field matches the requested name — see
//!    [`load_case`]. A mismatch is a fixture-edit bug
//!    ([`CaseError::NameMismatch`]).
//!
//! Bidirectional consistency between [`KNOWN_CASES`] and the on-disk
//! `fixtures/cases/*.json` set is enforced by the
//! `known_cases_matches_on_disk_fixtures` test below.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Every case the binary knows how to load. Adding a new case requires:
/// 1. A new entry here (alphabetical-ish, but grouped by failure family).
/// 2. A matching `fixtures/cases/<name>.json` file.
/// 3. A matching `fixtures/logs/<name>.log` file.
/// 4. A `[rules.<rule_name>]` section in `prose.toml` if the case
///    triggers a rule that doesn't already exist.
///
/// The `known_cases_matches_on_disk_fixtures` test enforces (1)+(2)
/// stay in sync; new fixture without a constant entry — or vice versa —
/// breaks `cargo test`.
pub const KNOWN_CASES: &[&str] = &[
    "auth_missing",
    "bad_payload",
    "rate_limit",
    "webhook_signature",
    "timeout",
    "dns_config",
    "tls_failure",
    "injection_attempt",
];

/// Errors the case loader can produce.
///
/// The variants are designed to support a meaningful exit-code mapping
/// in any binary that uses this crate. The `llm-assisted-api-debugging-lab` binary in
/// this repo follows the convention:
///
/// - `Unknown` → exit code 2 (caller passed a bad name).
/// - `Io`, `Parse`, `NameMismatch` → exit code 3 (a fixture file is
///   broken).
///
/// The distinction matters for `set -e`-style shell integration where
/// the caller wants to react differently to "you misspelled the
/// argument" vs "the on-disk fixture is corrupt." Library consumers can
/// adopt the same convention or pick their own.
#[derive(Debug, Error)]
pub enum CaseError {
    #[error("unknown case: {0}")]
    Unknown(String),
    #[error("could not read case file {0}: {1}")]
    Io(PathBuf, #[source] std::io::Error),
    #[error("could not parse case file {0}: {1}")]
    Parse(PathBuf, #[source] serde_json::Error),
    #[error("case file {path} declares name {found:?} but was loaded as {expected:?}")]
    NameMismatch {
        path: PathBuf,
        expected: String,
        found: String,
    },
}

/// One sanitized HTTP transaction, plus environmental context, plus a
/// pointer to the log file that recorded it.
///
/// The shape mirrors what an on-call engineer would attach to an
/// escalation: the request that went out, the response that came back
/// (if any), what the caller's own stack observed at the network layer
/// (`Context`), and a pointer to the relevant log slice.
#[derive(Debug, Clone, Deserialize)]
pub struct Case {
    /// Stable case identifier; must match the JSON file's basename.
    pub name: String,
    /// One-line human description of what this fixture exercises.
    /// Currently consumed only by docs/snapshots; not load-bearing.
    #[serde(default)]
    pub description: String,
    pub request: Request,
    /// Absent for connection-layer failures (DNS, TLS, timeout) where no
    /// response was received.
    #[serde(default)]
    pub response: Option<Response>,
    #[serde(default)]
    pub context: Context,
    /// Path to the log file relative to the project root. Resolved by
    /// [`log_path_for`].
    #[serde(default)]
    pub log_path: Option<PathBuf>,
}

/// Sanitized HTTP request as authored in the fixture file.
#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    pub method: String,
    pub url: String,
    /// `BTreeMap` rather than `HashMap` so the iteration order is stable
    /// for snapshot tests. Header lookups are O(log n) but with ~6
    /// headers per fixture that's irrelevant.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// One-line summary of the request body. Sensitive values are masked
    /// with `***` at fixture-authoring time; the diagnoser does not
    /// further redact.
    #[serde(default)]
    pub body_summary: String,
    #[serde(default)]
    pub client_unix_ts: Option<i64>,
    /// Client-side timeout budget. Compared against
    /// `Context::elapsed_ms_before_abort` to detect timeouts.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

/// Sanitized HTTP response. Absent on `Case` (i.e. `Case::response` is
/// `None`) for connection-layer failures where no response was received.
#[derive(Debug, Clone, Deserialize)]
pub struct Response {
    pub status: u16,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body_summary: String,
    #[serde(default)]
    pub server_unix_ts: Option<i64>,
    #[serde(default)]
    pub elapsed_ms: Option<u64>,
}

/// Environmental observations from the caller's own network stack —
/// things that don't appear in the HTTP transaction itself.
///
/// All fields are `Option` and `#[serde(default)]` so a fixture only
/// needs to set the ones relevant to its failure mode. Unset fields are
/// "we didn't observe this," not "we observed it as zero."
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Context {
    /// `Some(false)` means DNS resolution was attempted and failed;
    /// `Some(true)` or `None` means it either succeeded or wasn't
    /// reached.
    #[serde(default)]
    pub dns_resolved: Option<bool>,
    #[serde(default)]
    pub dns_error: Option<String>,
    #[serde(default)]
    pub dns_host: Option<String>,
    /// Time spent in TLS handshake on a successful connection.
    #[serde(default)]
    pub tls_handshake_ms: Option<u64>,
    /// `Some(true)` indicates the handshake was attempted and failed.
    #[serde(default)]
    pub tls_handshake_failed: Option<bool>,
    #[serde(default)]
    pub tls_failure_reason: Option<String>,
    #[serde(default)]
    pub tls_peer: Option<String>,
    /// Skew between the client's clock and the server's, in seconds.
    /// Sign indicates direction (negative = client behind server).
    /// Absolute value is what gets compared to `signature_tolerance_secs`.
    #[serde(default)]
    pub client_clock_skew_secs: Option<i64>,
    /// Set by webhook-receiver fixtures; toggles whether clock-skew
    /// evidence is even meaningful for this case.
    #[serde(default)]
    pub signing_required: Option<bool>,
    /// HMAC tolerance window in seconds.
    #[serde(default)]
    pub signature_tolerance_secs: Option<u64>,
    /// Set when middleware re-encoded the JSON body between the wire and
    /// HMAC verification. Drives the `BodyMutatedBeforeVerification`
    /// evidence variant.
    #[serde(default)]
    pub body_mutated_before_verification: Option<bool>,
    /// Wall-clock time the client spent waiting before giving up on a
    /// non-arriving response.
    #[serde(default)]
    pub elapsed_ms_before_abort: Option<u64>,
    /// Free-text error string from the caller's network stack. Used for
    /// rendering only; rules don't read this directly.
    #[serde(default)]
    pub connection_error: Option<String>,
}

/// Look up the on-disk path for a known case name. Returns `Err(Unknown)`
/// when the name is not in `KNOWN_CASES`.
pub fn case_fixture_path(fixtures_dir: &Path, name: &str) -> Result<PathBuf, CaseError> {
    if !KNOWN_CASES.contains(&name) {
        return Err(CaseError::Unknown(name.to_string()));
    }
    Ok(fixtures_dir.join("cases").join(format!("{name}.json")))
}

/// Load a single case fixture by name from the given fixtures directory.
///
/// Asserts that the loaded fixture's `name` field matches the requested
/// name; a mismatch returns `CaseError::NameMismatch` rather than silently
/// producing a wrong-cased diagnosis.
pub fn load_case(fixtures_dir: &Path, name: &str) -> Result<Case, CaseError> {
    let path = case_fixture_path(fixtures_dir, name)?;
    let bytes = std::fs::read(&path).map_err(|e| CaseError::Io(path.clone(), e))?;
    let case: Case =
        serde_json::from_slice(&bytes).map_err(|e| CaseError::Parse(path.clone(), e))?;
    if case.name != name {
        return Err(CaseError::NameMismatch {
            path,
            expected: name.to_string(),
            found: case.name,
        });
    }
    Ok(case)
}

/// Resolve the log file path for a case, relative to the fixtures directory's
/// parent (so a case that records `fixtures/logs/foo.log` resolves correctly
/// regardless of the current working directory).
pub fn log_path_for(case: &Case, project_root: &Path) -> Option<PathBuf> {
    case.log_path.as_ref().map(|p| project_root.join(p))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
    }

    #[test]
    fn known_cases_all_load() {
        for name in KNOWN_CASES {
            let case =
                load_case(&fixtures_dir(), name).unwrap_or_else(|e| panic!("loading {name}: {e}"));
            assert_eq!(case.name, *name, "case file name field must match filename");
        }
    }

    #[test]
    fn unknown_case_is_rejected() {
        let err = load_case(&fixtures_dir(), "not_a_real_case").unwrap_err();
        assert!(matches!(err, CaseError::Unknown(_)));
    }

    #[test]
    fn known_cases_matches_on_disk_fixtures() {
        let cases_dir = fixtures_dir().join("cases");
        let mut on_disk: Vec<String> = std::fs::read_dir(&cases_dir)
            .unwrap_or_else(|e| panic!("reading {}: {e}", cases_dir.display()))
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
            .filter_map(|p| p.file_stem().and_then(|s| s.to_str()).map(str::to_string))
            .collect();
        on_disk.sort();
        let mut declared: Vec<String> = KNOWN_CASES.iter().map(|s| s.to_string()).collect();
        declared.sort();
        assert_eq!(
            declared, on_disk,
            "KNOWN_CASES must match the set of *.json files under fixtures/cases/"
        );
    }

    #[test]
    fn name_mismatch_is_rejected() {
        // Write a temporary case file that declares the wrong name.
        let dir = std::env::temp_dir().join("llm-assisted-api-debugging-lab-name-mismatch");
        let cases_dir = dir.join("cases");
        std::fs::create_dir_all(&cases_dir).unwrap();
        let bogus = cases_dir.join("auth_missing.json");
        std::fs::write(
            &bogus,
            r#"{"name":"rate_limit","request":{"method":"GET","url":"http://x"}}"#,
        )
        .unwrap();
        let err = load_case(&dir, "auth_missing").unwrap_err();
        assert!(
            matches!(err, CaseError::NameMismatch { .. }),
            "expected NameMismatch, got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
