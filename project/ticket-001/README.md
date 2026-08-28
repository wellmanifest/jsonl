# Ticket 001: Define governed JSONL standard

- **ID**: ticket-001
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-08-28

## Goal and scope

Define a dependency-free, deterministic JSON Lines framing standard for strict
LLM output, arbitrary DSL payloads, runtime sealing and debug logs. Keep record
framing separate from semantic event ownership in `wellmanifest/logs`.

## Acceptance criteria

- [x] AC-01: Candidate and sealed-record JSONL contracts reject malformed,
  ambiguous, oversized and hash-drifted lines.
- [x] AC-02: A strict GBNF projection lets an LLM emit one candidate JSON
  object per line without runtime-owned authority or receipt fields.
- [x] AC-03: The DSL manifest binds all normative artifacts and pins the
  `wellmanifest/dsl` contract plus declared `autogrammar/*` adapters.
- [x] AC-04: Dependency-free conformance self-tests and example validation
  pass, including truncation and non-object negative cases.
- [ ] AC-05: Publication uses exact-head independent Validator approval.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-codex.md](ai-codex.md)
