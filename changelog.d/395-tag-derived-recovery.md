### Changed

- Derive the source-release recovery window from the repository's own tag
  ledger instead of a hand-frozen table: an owner-prepared annotated tag is the
  freeze, and every fact the table transcribed is re-derived from git and the
  API at run time.
- Replace the executor membership refusal and its per-edge pins with the
  executor relation — a recovery publisher is a later first-parent commit of
  protected main than the source it drains, proved against the checkout.
- Prove the predecessor rather than all of history, so one dispatch's read and
  byte budgets follow the backlog and never the number of releases published.
- Drain every pending edge in one dispatch, in ledger order, stopping at the
  first refusal, with an independent readback after each edge.
- Name every silent failure: non-201 identity-asset uploads print their HTTP
  status and a bounded response slice, every write-boundary refusal names the
  check that refused, and each run logs per-edge and per-run summaries.
