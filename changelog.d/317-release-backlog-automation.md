### Fixed

- Accept git's canonical single-newline annotated-tag message encoding
  alongside the REST publisher's unterminated form, so owner-prepared release
  tags made with `git tag -a -m` walk the immutable ledger; target, tagger
  identity and tagger instant stay exact.
- Derive the source-release backlog from the publisher's own ledger rules and
  prepare every missing owner tag with one command, replacing the hand-written
  tag ceremony without moving tag-creation authority into CI.
- Report a stalled source-release backlog daily as one read-only
  `deploy-assurance[release-backlog]` issue instead of leaving it unnoticed.
