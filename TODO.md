# TODO

- [x] Define distinct propose-only candidate and runtime-sealed record
  envelopes with UTF-8/LF framing and bounded line size.
- [x] Validate ordering, canonical hashes, truncation, non-object values and
  forbidden runtime-owned fields without third-party dependencies.
- [x] Publish a strict GBNF projection and a digest-bound wellmanifest/dsl
  manifest with declared `autogrammar/data2dsl` and `autogrammar/nlp2dsl`
  adapters.
- [x] Validate a canonical candidate example locally; protected publication is
  tracked by ticket-001 through its exact-head Validator receipt.
- [ ] Adopt the released pack in the status-cycle and Subactor Supervisor
  integration tickets.
