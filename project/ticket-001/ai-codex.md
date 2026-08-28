---
participant-id: agent:codex
participant: codex
role: agent
ticket: ticket-001
---
# Participant: codex (AI agent)

## Understanding

The user needs a reusable line-oriented boundary between LLM-generated JSON,
any declared DSL grammar and durable runtime/debug logs. JSONL framing must be
generic, while payload semantics and execution authority remain external.

## Execution plan

1. Define separate propose-only candidate and runtime-sealed record contracts.
2. Bind a strict candidate GBNF and arbitrary DSL references through the
   wellmanifest/dsl manifest.
3. Implement dependency-free validation, sealing and negative self-tests.
4. Validate examples, governance and protected publication.

## Actual changes

- Initialized the bounded ticket and recorded SESSION_EXECUTION_AUTHORIZATION
  from the request to execute this work.
- Created the public `wellmanifest/jsonl` HOME repository and adopted the
  immutable `wellmanifest/new-project` v0.18.10 package.
- Added closed candidate and sealed-record envelopes, strict GBNF, canonical
  examples, deterministic validation/sealing and a digest-bound DSL manifest.
- Verified positive streams plus malformed UTF-8 framing, truncation, blank
  lines, non-object values, duplicate keys and hash-chain drift fail closed.

## Blockers

- None inside the recorded intent; proceed without a second confirmation.
- New authority remains required for destructive action, secret access, new
  external coordination or material objective expansion. Protected delivery
  may be invoked without another prompt when publication is in scope; its
  exact-head trusted approval remains independent evidence.
