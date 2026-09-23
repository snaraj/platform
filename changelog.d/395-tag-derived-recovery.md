### Changed

- Derive the source-release recovery window from the repository's own tag ledger instead of a hand-frozen table, so an owner-prepared annotated tag is the freeze.
- Replace the executor membership refusal and its per-edge pins with the executor relation, proved against the checkout on main's own first-parent line.
- Prove the predecessor rather than all of history, so one dispatch's read and byte budgets follow the backlog and never the number of releases published.
- Drain every pending edge in one dispatch, in ledger order, stopping at the first refusal, with an independent readback after each edge.
- Name every silent failure: non-201 identity-asset uploads print their HTTP status and a bounded response slice, and every write-boundary refusal names the check that refused.
