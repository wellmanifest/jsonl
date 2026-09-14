# Ticket 003: Adopt governance 0.20.29 as the activity batching canary

- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-09-14
- **Workstream**: governance
- **Issue**: https://github.com/wellmanifest/jsonl/issues/4

## Plan and acceptance

- [ ] AC-01: Apply the final published source with goal governance adopt; verify its immutable pin, governance and unchanged JSONL tests before protected publication.

Session authorization covers this fleet update and the independent Validator merge. The source release is a prerequisite: no unpublished production adoption or direct managed edits. Preserve all target-owned configuration. Record Issue, canonical worktree, branch, lease and PR in the existing project Planfile; raw receipts remain external in activity-batch-230-20260914. After publication, record the actual tested source revision and terminal result outside Git.

Published source: `a4178b9cf6fa12540ee7406d7f38391dd4fa1f30` (0.20.29). The managed upgrade changes 16 files. Refresh the target-owned S2 adoption inventory from the verified generated lock; preserve its audit mode and existing level. Eight pre-existing profile-level/missing-pack findings remain outside this bounded package upgrade.
