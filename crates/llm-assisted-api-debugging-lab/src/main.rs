//! Thin CLI shell. All real work happens in the library crate.
//!
//! Responsibilities of this binary:
//! - Parse command-line arguments via `clap`'s derive macros.
//! - Load fixtures from disk, read log files.
//! - Dispatch to the right library function for each subcommand.
//! - Map any [`CaseError`] back to a meaningful POSIX exit code.
//!
//! The binary makes no decisions of its own about diagnoses, prompt
//! content, or output format — those live in the library so they can be
//! exercised from tests without spawning a subprocess.
//!
//! [`CaseError`]: llm_assisted_api_debugging_lab::cases::CaseError

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use llm_assisted_api_debugging_lab::cases::{load_case, log_path_for, KNOWN_CASES};
use llm_assisted_api_debugging_lab::{
    collect_evidence, diagnose, parse_log, render_prompt, render_prompt_json, render_report,
    render_short, Diagnosis,
};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "llm-assisted-api-debugging-lab",
    version,
    about = "LLM-Assisted API Debugging Lab CLI"
)]
struct Cli {
    /// Path to the fixtures directory. Defaults to ./fixtures relative to CWD.
    #[arg(long, default_value = "fixtures", global = true)]
    fixtures_dir: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// List the case names this lab ships fixtures for.
    ListCases,
    /// Diagnose a known case and print a short summary.
    Diagnose { name: String },
    /// Diagnose by parsing only the given log file (no JSON case fixture).
    DiagnoseLog { path: PathBuf },
    /// Diagnose a known case and print the full report.
    Report { name: String },
    /// Render the LLM prompt template for a known case.
    Prompt { name: String },
    /// Render the LLM prompt as a JSON envelope (for typed-output model APIs).
    PromptJson { name: String },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(exit_code_for(&e))
        }
    }
}

/// Subcommand dispatch. Returns `Ok(())` on success; any error is mapped
/// to a POSIX exit code by [`exit_code_for`] in `main`.
fn run(cli: &Cli) -> Result<()> {
    match &cli.cmd {
        Cmd::ListCases => {
            for name in KNOWN_CASES {
                println!("{name}");
            }
            Ok(())
        }
        Cmd::Diagnose { name } => {
            let d = build_diagnosis(&cli.fixtures_dir, name)?;
            print!("{}", render_short(&d));
            Ok(())
        }
        Cmd::DiagnoseLog { path } => {
            let log_text = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            let evidence = parse_log(&log_text);
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("log")
                .to_string();
            let d = diagnose(&name, &evidence);
            print!("{}", render_short(&d));
            Ok(())
        }
        Cmd::Report { name } => {
            let d = build_diagnosis(&cli.fixtures_dir, name)?;
            print!("{}", render_report(&d));
            Ok(())
        }
        Cmd::Prompt { name } => {
            let d = build_diagnosis(&cli.fixtures_dir, name)?;
            print!("{}", render_prompt(&d));
            Ok(())
        }
        Cmd::PromptJson { name } => {
            let d = build_diagnosis(&cli.fixtures_dir, name)?;
            let value = render_prompt_json(&d);
            println!(
                "{}",
                serde_json::to_string_pretty(&value)
                    .with_context(|| format!("serializing prompt-json for {name}"))?
            );
            Ok(())
        }
    }
}

/// Load a case by name, read its associated log file, and run the rules
/// engine. This is the common path shared by `diagnose`, `report`,
/// `prompt`, and `prompt-json`.
///
/// The `project_root` derivation (`fixtures_dir.parent()`) makes
/// `case.log_path` (which is recorded as e.g. `fixtures/logs/foo.log`,
/// rooted at the project) resolve correctly even when the caller passes
/// a custom `--fixtures-dir` outside the default `./fixtures` location.
fn build_diagnosis(fixtures_dir: &Path, name: &str) -> Result<Diagnosis> {
    let case = load_case(fixtures_dir, name).with_context(|| format!("loading case {name}"))?;
    let project_root = fixtures_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let log_text = match log_path_for(&case, &project_root) {
        Some(p) => {
            std::fs::read_to_string(&p).with_context(|| format!("reading log {}", p.display()))?
        }
        None => String::new(),
    };
    let evidence = collect_evidence(&case, &log_text);
    Ok(diagnose(name, &evidence))
}

/// Map an `anyhow::Error` to a POSIX exit code by walking the error
/// chain for a [`CaseError`]. If we find one, we distinguish "caller
/// passed a bad name" (exit 2) from "fixture is broken" (exit 3) so a
/// shell wrapper can react appropriately. Any other error is generic
/// failure (exit 1).
///
/// We check both the leaf error and the full chain because `anyhow`'s
/// `with_context` wraps each `Err` in a new outer error, which means a
/// `CaseError` produced by `load_case` arrives at `main` as the *cause*
/// of a contextual outer error rather than the leaf type itself.
///
/// [`CaseError`]: llm_assisted_api_debugging_lab::cases::CaseError
fn exit_code_for(err: &anyhow::Error) -> u8 {
    use llm_assisted_api_debugging_lab::cases::CaseError;
    let mapped = err
        .downcast_ref::<CaseError>()
        .or_else(|| err.chain().find_map(|e| e.downcast_ref::<CaseError>()));
    match mapped {
        Some(CaseError::Unknown(_)) => 2,
        Some(CaseError::Io(_, _) | CaseError::Parse(_, _) | CaseError::NameMismatch { .. }) => 3,
        None => 1,
    }
}
