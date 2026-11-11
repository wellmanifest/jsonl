# Ticket 005: Harden JSONL framing, authority diagnostics, and generation-request validation

- **ID**: ticket-005
- **Owner**: agent:antigravity
- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-11-11

## Session authorization

- `SESSION_EXECUTION_AUTHORIZATION`: Autonomous execution, testing, and protected publication requested by the repository owner.

## Goal and scope

Harden `standard/jsonl_check.py` and repository pytest integration so that:

1. `validate_candidate()` checks forbidden `RUNTIME_OWNED` fields (`JSONL-MODEL-AUTHORITY`) before generic envelope key comparison (`JSONL-CANDIDATE-FIELDS`), ensuring candidate attempts to smuggle runtime-owned fields emit `JSONL-MODEL-AUTHORITY`.
2. `read_stream()` splits raw bytes strictly on LF (`b"\n"`), validates empty lines and `MAX_LINE_BYTES` before per-line UTF-8 decoding, avoids double UTF-8 encoding, and preserves valid JSON strings containing Unicode line separators (`\u2028`, `\u2029`, `\u0085`).
3. Both `validate_record()` and `seal()` enforce strict RFC 3339 date-time timestamps with explicit timezone offsets (`JSONL-TIME`), and `validate_record()` enforces non-empty token grammar on `recordId` and `receiptRef`.
4. `validate --profile generation-request` validates `wellmanifest.jsonl/generation-request/v1` streams declared in `contracts/jsonl.contract.json`.
5. `pyproject.toml`, `profiles/dsl-manifest.json`, and `standard/test_jsonl_check.py` provide standalone `pytest` coverage and digest synchronization.

## Acceptance criteria

- [x] AC-01: `JSONL-MODEL-AUTHORITY` fires whenever any runtime-owned field appears in a candidate object.
- [x] AC-02: `read_stream()` frames raw bytes strictly by `LF`, preserves Unicode separators inside JSON strings, and enforces `MAX_LINE_BYTES` before UTF-8 decode.
- [x] AC-03: Strict RFC 3339 timestamps, `recordId`/`receiptRef` tokens, `generation-request` validation, `profiles/dsl-manifest.json` digest, `pytest`, and governance gates pass.
