### Fixed

- Make `scripts/edge-probe.sh --zone <one zone>` finish its report instead of aborting on an unset variable when there is no other site to compare titles against, with a regression test that drives the real function through a stubbed fetch.
- State in `SECURITY.md` that Private Vulnerability Reporting is enabled and is the private route for reports, replacing text that told reporters it was disabled; the policy test now pins the enabled wording and still fails if it is inverted or a required sentence is removed.
- Advance the CodeQL actions to 4.39.1 and `actions/create-github-app-token` to 3.3.0 by full commit SHA, folding the two Dependabot proposals that could not carry this fragment themselves.
