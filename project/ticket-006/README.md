# Ticket 006: Harden JSONL stream I/O, symlink traversal, number/surrogate bounds, RFC3339 subseconds, and URI traversal

- **ID**: ticket-006
- **Owner**: tom
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-11-11

## Goal and scope

SESSION_EXECUTION_AUTHORIZATION: On 2026-11-11 user authorized auditing, fixing bugs, optimizing, and hardening `wellmanifest/*` standard repositories.

Harden `standard/jsonl_check.py` (`< 500L`) against symlink files, symlink-parent traversal (`sym_dir/..`, `../sym_dir`) before `os.path.abspath`, non-regular files (FIFOs/devices/directories), inode swaps (`lstat`/`fstat`), and unbounded streams (`<= 16 MiB`, `<= 10000` records); bound JSON integer digit lengths (`<= 309`), finite floats (`1e999` -> `JSONL-NUMBER`), nesting depth (`<= 64` -> `JSONL-DEPTH`), and lone UTF-16 surrogates (`JSONL-UTF8`) across both `read_stream` and programmatic `validate_*` / `seal` entrypoints; anchor regexes with `\A...\Z` and normalize 7–9 digit RFC3339 fractional seconds; reject control characters and `..` path traversal in `receiptRef`, `correlationId`, and `dsl` bindings; synchronize `profiles/dsl-manifest.json` SHA-256 digest; expand `standard/test_jsonl_check.py`; and mark merged `project/ticket-005/README.md` `DONE`.

## Acceptance criteria

- [x] AC-01: Enforce regular-file non-symlink stream I/O with symlink-parent traversal protection, finite 309-digit integer/float/depth/UTF-8 surrogate validation, 7–9 digit RFC3339 fractional seconds, and `..` traversal rejection in `standard/jsonl_check.py` (`< 500L`), and mark `project/ticket-005/README.md` `DONE`.
- [x] AC-02: Synchronize `profiles/dsl-manifest.json` SHA-256 digest and pass `ruff check --no-cache standard`, `python3 standard/jsonl_check.py self-test`, `python3 standard/jsonl_check.py validate --profile candidate --file examples/candidates.jsonl`, `pytest -q`, `./project/governance-check.sh --base origin/main`, and `wellman check` with 0 errors.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
