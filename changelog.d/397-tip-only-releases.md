### Changed

- Platform source releases are tip-only: a run publishes only the green protected-main tip it executes at, and one Release binds every fragment merged since the previous Release, so merging is the owner's only routine release action.
- A new v5 signed identity binds every fragment path and digest and names the evidence job whose success finalizes the Release; a failure after the immutable flip can no longer strand it, and no later attempt substitutes for the signed one.
- An hourly reconciliation publishes a green tip that a lost, replaced or failed trigger left unreleased; pre-commit leftovers are discarded and committed Releases are finalized without re-signing.
- The issue #369 recovery workflow, its reader, the owner-prepared tag command and the predecessor waiter are removed; the terminal per-merge Release `v0.1.94` and every earlier identity still verify under their original rules.
