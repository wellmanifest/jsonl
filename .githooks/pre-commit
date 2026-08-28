#!/usr/bin/env bash
# Managed adopter hook: bind implementation to an active ticket. The payload
# is separate from the hub's live hook so later runtime composition does not
# mutate the standard source's own enforcement while it is executing.

set -euo pipefail

root="$(git rev-parse --show-toplevel)"
branch="$(git symbolic-ref --short HEAD 2>/dev/null || true)"

run_worktree_guard() {
  local runner="$root/.governance/worktree_guard.py"
  if [[ -f "$runner" ]]; then
    python3 "$runner" --root "$root" --once
    return
  fi

  echo "worktree-guard: the managed pre-commit hook cannot find worktree_guard.py." >&2
  echo "  Restore the managed package or reinstall the repository guard:" >&2
  echo "    ./scripts/install-worktree-guard.sh --target $root --wire-hook" >&2
  return 1
}

if [[ -z "$branch" || "$branch" == "HEAD" ]]; then
  echo "GOV-AGENT-HOST-001: detached HEAD is not bound to ticket-NNN." >&2
  exit 1
fi

if [[ ! "$branch" =~ ticket[-/]([0-9]{3}) ]]; then
  echo "GOV-AGENT-HOST-001: branch '$branch' is not bound to ticket-NNN." >&2
  echo "  Allocate with ./project/new-ticket.sh and commit on a ticket branch." >&2
  exit 1
fi

ticket="ticket-${BASH_REMATCH[1]}"
readme_rel="project/$ticket/README.md"

if ! staged_readme="$(git show ":$readme_rel" 2>/dev/null)"; then
  echo "GOV-AGENT-HOST-002: $root/$readme_rel is missing from the staged snapshot." >&2
  echo "  Allocate with ./project/new-ticket.sh; do not invent a ticket number." >&2
  exit 1
fi

if grep -Eiq '^-[[:space:]]+\*\*Status\*\*:[[:space:]]*IN_PROGRESS([[:space:]]|$)' <<<"$staged_readme"; then
  run_worktree_guard
  exit 0
fi

if grep -Eiq '^-[[:space:]]+\*\*Status\*\*:[[:space:]]*(DONE|CANCELLED)([[:space:]]|$)' <<<"$staged_readme"; then
  if git diff --cached --quiet -- "$readme_rel"; then
    echo "GOV-AGENT-HOST-003: $ticket terminal closure does not stage its ticket README." >&2
    echo "  Stage the terminal ticket evidence in the same governance-only commit." >&2
    exit 1
  fi
  if ! git diff --cached --quiet --diff-filter=DRC --; then
    echo "GOV-AGENT-HOST-003: $ticket terminal closure contains a deletion, rename or copy." >&2
    echo "  A terminal closure may only add or modify its bounded governance evidence." >&2
    exit 1
  fi

  mapfile -d '' -t staged_paths < <(git diff --cached --name-only -z --diff-filter=AM --)
  if [[ "${#staged_paths[@]}" -eq 0 ]]; then
    echo "GOV-AGENT-HOST-003: $ticket terminal closure has no staged governance evidence." >&2
    exit 1
  fi
  for path in "${staged_paths[@]}"; do
    case "$path" in
      "project/$ticket/"*|TODO.md|project/TICKETS.md|config/artifact-registry.json) ;;
      *)
        echo "GOV-AGENT-HOST-003: $ticket terminal closure contains non-closure path '$path'." >&2
        echo "  Keep implementation on an IN_PROGRESS ticket; closure is governance-only." >&2
        exit 1
        ;;
    esac
  done
  run_worktree_guard
  exit 0
fi

echo "GOV-AGENT-HOST-003: $ticket is neither IN_PROGRESS nor a valid staged terminal closure." >&2
echo "  Return implementation to IN_PROGRESS or stage only terminal closure evidence." >&2
exit 1
