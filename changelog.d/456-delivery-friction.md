### Changed

- Grade the daily software-currency run by evidence: every row is CURRENT, UPDATE or UNKNOWN, UPDATE rows are listed in the job summary, and only an unverifiable upstream version fails the run.
- Advance the lockstep CodeQL `init` and `analyze` pins from 4.39.1 to 4.39.2 at the commit peeled from the upstream tag, superseding Dependabot PR #455, and add `make adopt-dependabot`, which re-derives a Dependabot action-pin PR from its diff as data onto current main as one signed commit with its release fragment and refuses every other line or path.
- Let `scripts/ready_check.py` carry the review App's APPROVE to a re-cut or rebased head only when the old head is GitHub-recorded for the source PR and the whole-file verbatim patch identity is unchanged; every check must still pass at the new head.
- Scan the pinned obsync proxy image in pull-request and main CI only when the change touches what defines or scans it, and scan it on every scheduled-security run.
- Accept `pool` lines and retry a lost NTP datagram in the hardening verifier, start the sysctl re-apply unit when it is enabled, and pin the probe's length and mode checks and the re-apply unit's forbidden options in tests.
- Expect DNSSEC signed and validating on lidersea.com in the edge probe.
- State in AGENTS.md that the coordinator merges a Ready PR and drives delivery, with unchanged conditions, and that a behind PR is re-cut with its review kept only for a byte-identical change.
