# GOV-WORK-START-001 — work admission before allocation

## Situation

A new task would overlap pending work, exceed the workstream limit, or start
from incomplete branch/worktree observations. An unbound branch rejected by
the commit hook is not necessarily a Git merge conflict.

## Meaning

The query reads registered worktrees, local branch contributions, dirty paths,
branch-owned intent and the managed activity resolver. It does not authorize a
writer, transfer a lease, refresh remotes, allocate a ticket or close old work.
The complete report is clone-local and may contain private filesystem paths;
keep it in private receipt storage, not a tracked ticket.

## Safe resolution

| Route | Use | Boundary |
| --- | --- | --- |
| REUSE_EXISTING | Continue the matching canonical ticket checkout. | Revalidate intent, owner and current lease first. |
| ASSIST_READ_ONLY | Help an active delivery with analysis or review. | No second writer or trusted self-approval. |
| HANDOFF_REQUIRED | Reconcile pending work from an inactive ticket. | Accepted scope, snapshot and controller CAS; no automatic takeover. |
| SERIALIZE | Workstream capacity is occupied. | Queue without another delivery worktree. |
| RECONCILE | Owner, ancestry, pending branch or observations are uncertain. | Preserve work and resolve the specific missing evidence. |
| NEW_TICKET_CANDIDATE | Scope and WIP capacity permit new allocation. | Planning candidate only; never write authority. |

```text
task -> registered clone observation
          |-> existing work -> reuse / assist / handoff / queue
          |-> uncertainty   -> reconcile; preserve data
          `-> free scope    -> managed allocation candidate
                                -> intent + owner + fencing + gate -> one writer
```

1. Run `python3 scripts/work_start_check.py --root . --workstream <declared-id>`
   (adopters use `.governance/work_start_check.py`). Add `--ticket ticket-NNN`
   for an explicit continuation; optionally narrow with repeatable `--path`.
2. Follow the route: REUSE_EXISTING, ASSIST_READ_ONLY, HANDOFF_REQUIRED,
   SERIALIZE, RECONCILE or NEW_TICKET_CANDIDATE. Finish existing authorized
   work first. Read-only assistance is not permission to edit another writer's
   files or self-approve their PR.
3. Handoff requires an accepted scope and controller-owned compare-and-swap
   lease transfer/reacquisition, a restorable snapshot and exact-head checks.
   If unavailable, queue the affected work without a delivery worktree.
4. Keep disjoint authorized work moving. Do not count a clean integrated
   historical checkout as a new pending delivery merely because it exists.
5. Reobserve immediately before allocation and before writing; verify intent,
   owner, fencing and the governance gate at the effect boundary. A saved
   report is evidence, never a replayable admission token.

## Verification

Report `new-project.work-start-report/v1` uses closed schema
`urn:wellmanifest:new-project:schema:work-start-report:v1`. It binds refs,
intent and dirty-content digests, including changes to already dirty files.
The helper, schema and this runbook ship through the immutable package.
Files and opted-in SQLite ticket input use the managed activity resolver.

`python3 tests/work_start_test.py` checks real Git fixtures and no-write queries.
The managed allocator invokes `--allocation-check` under its clone-wide ID
lock before reserving a number. A rejected attempt leaves no new ticket,
high-water reservation or worktree. The query exit code alone does not
authorize development; REUSE_EXISTING also requires the current writer lease.

This is not a global scheduler or an editor lock. Independent clones, live
GitHub state, processes and writer authority require separate observations.
The query does not fetch or verify a lease. Recheck it at the effect boundary;
the allocator's ID lock does not replace writer fencing. Unborn seed bootstrap
retains its separate contract, not a development-gate exemption.

## Do not

- Do not use `--force-new`, rename a branch or disable hooks to bypass admission.
- Do not merge, reset, clean, delete, stage or copy foreign work automatically.
- Do not guess owners, remote freshness or independent-clone state from Git.
- Do not treat BLOCKED/PLAN as permission to take a dirty checkout.
- Do not repeat allocation to resolve a missing observation.

## Related rules

P-WORKSPACE-005, P-WORKSPACE-006, C-START-004, C-CONCURRENCY-005,
P-CORE-014, P-TICKET-ACTIVITY-001 and P-LEASE-001.
