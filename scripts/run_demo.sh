#!/usr/bin/env bash
# Five-minute demo path. Run from the repository root.
#
# Builds the CLI once, then exercises each top-level subcommand against the
# bundled fixtures. No network calls, no API keys.

set -euo pipefail

cd "$(dirname "$0")/.."

hr() { printf '\n----- %s -----\n' "$1"; }

hr "build"
cargo build --quiet --locked --release -p llm-assisted-api-debugging-lab

BIN="./target/release/llm-assisted-api-debugging-lab"

hr "list-cases"
"$BIN" list-cases

hr "diagnose webhook_signature"
"$BIN" diagnose webhook_signature

hr "diagnose-log fixtures/logs/timeout.log"
"$BIN" diagnose-log fixtures/logs/timeout.log

hr "report rate_limit"
"$BIN" report rate_limit

hr "prompt webhook_signature"
"$BIN" prompt webhook_signature

hr "prompt-json webhook_signature"
"$BIN" prompt-json webhook_signature

hr "prompt injection_attempt (sanitized)"
"$BIN" prompt injection_attempt
