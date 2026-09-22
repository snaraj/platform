# Published release-identity fixtures — provenance

`v0.1.81-platform-release-identity.v4.json` is the **immutable asset itself**,
byte for byte, downloaded from Release `387789735` (`v0.1.81`) as
`platform-release-identity.v4.json`: 1614 bytes, sha256
`4e9cfb1bdbdd27cf8fac42905f5832e3f24a5a24fe2c6636cf63cdabb95db119`, the digest
the REST release record reports for that asset. Nothing was edited — the test
asserts the digest, so an edited copy fails there first.

It carries only already-public facts: the repository name and object ID, source
and executor commit SHAs, workflow run IDs, the fragment path and its SHA-256,
and the schema URL. No credential, host, path or account identifier appears in
it.

It exists because a hand-written sample would not have caught the defect it
pins (issue #391). The executor this signed payload records, `10ee0a67`, later
became the frozen source of `v0.1.91`, so the window's membership refusal
turned against an edge that was already published and can never be reissued.
Only the real bytes prove the repair admits this exact published identity, and
that the pre-repair rule refuses it.
