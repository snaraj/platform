# Platform source releases and dependency queue

## Scope and authority

This runbook implements issue #164. It changes source-release bookkeeping only:
it grants no merge, tag, live-system, provider, cluster, deployment, or settings
authority. The owner alone merges, and merging is the owner's only routine
release action (issue #397). GitHub Actions may create only the annotated
platform source tag of the current protected-main tip and its immutable Release
with the exact signed identity asset pair, after the tip's CI, CodeQL and the
settings proof pass. `v0.1.40` is the sole zero-asset transition predecessor; it
is never the format for a new release.

## One fragment per pull request

Every pull request adds exactly one path shaped
`changelog.d/<issue>-<lowercase-slug>.md`. The file is immutable after addition
and contains exactly one `### Added`, `### Changed`, `### Fixed`, or
`### Security` heading, a blank line, and one or more non-empty Markdown bullets.
The gate rejects an absent or second fragment, edits/deletions/renames of an
existing fragment, malformed names or bytes, workflow-expression openers, and
any change to root `VERSION` or `CHANGELOG.md`.

`VERSION` and `CHANGELOG.md` remain frozen historical records through `v0.1.9`.
They are not current release inputs and are not publisher-maintained outputs.
The one remaining code read of those paths is the exact frozen `v0.1.0`
recovery proof; it cannot select or describe a post-migration release.

The same exact-base transition runs on pull requests and protected-main pushes.
A squash commit and a merge-free rebase range are both valid when their complete
range adds exactly one fragment. The fragment may be committed anywhere in a
multi-commit range. One pull request still adds one fragment; one Release binds
every fragment merged since the previous Release.

## Tip-only publication

The immutable `v0.1.9` tag and its exact source SHA are the migration floor.
From the floor forward, every platform tag is canonical `vX.Y.Z`, annotated with
the exact embedded name, source-bound message, GitHub Actions bot identity and
source-commit date, exactly one patch after its predecessor, and on one
merge-free ancestral sequence. Up to the terminal per-merge Release `v0.1.94`
(source `62f6ec1a51916e22956b72504e28a2932ee4b573`) each adjacent tag binds
exactly one fragment. Every later tag is a tip Release and binds every fragment
added since its predecessor, never zero. The validator refuses more than 1024
platform tag refs before walking the ledger.

A run publishes only the protected-main tip it executes at: `GITHUB_SHA`, whose
workflow and scripts are running, so the publisher is the source by
construction. The version is the latest Release plus one patch, one per Release,
never one per merge. `platform-release.yml` runs on every completed main CI and
hourly (`41 * * * *`); both triggers run the same jobs under one non-canceling
concurrency group, so publication has a single writer. Every run prints one
`RELEASE_DECISION` line; every refused check prints one `RELEASE_REFUSED` line;
every API call prints its status, and every job ends with a `RELEASE_SUMMARY`
of its request count, budget and duration.

| Observed state | Decision | Writes |
| --- | --- | --- |
| The run's commit is no longer the main tip | `none` (superseded) | none |
| The tip's main CI or CodeQL is missing or running | `none` (ci-pending) | none |
| The tip's main CI or CodeQL did not succeed | `none` (ci-red) | none |
| The latest Release verifies and fragments were added since | `publish` the next patch | evidence, then commit |
| The latest Release already names the tip, or nothing was added | `none` (current) | none |
| The latest tag is committed but its Release is still a staged draft | `finalize` | flip only |
| Anything else: a foreign or inexact tag or Release, a draft another author owns | `RELEASE_REFUSED` | none |

A superseded or pending run needs nothing: the newer tip's own run, or the next
hourly run, publishes it. GitHub may replace a pending run in queue order; that
never loses work, because every run re-derives the tip.

### Evidence, commit point and finalization

The `evidence` job holds `contents: write` and OIDC. It re-proves the tip and
the latest Release, deletes only this publisher's own drafts for exactly the
next tag (pre-commit leftovers of a failed run), creates the content-addressed
annotated tag object without a ref, creates a draft Release with the notes,
renders the v5 identity, signs it with Sigstore, uploads the identity and its
bundle, and re-downloads and re-validates both. Everything it writes is private
and disposable.

The `publish` job holds `contents: write` only. It proves the staged draft
again, then creates the tag ref, which is the commit point, and flips the draft
to an immutable Release. A lost flip response is judged by readback. Before the
commit point a failure is discarded by the next run; after it the transaction
only rolls forward: a committed tag whose staged draft verifies is finalized by
the next run with no new signature.

The v5 identity names the `evidence` job (run ID and attempt), and verifiers
require that job's own `completed/success` record, never the run's overall
conclusion and never a later attempt. A failure after the immutable flip
therefore cannot make a Release unverifiable, and no attempt substitutes for
the one its signature names. The identity binds every fragment path and SHA-256
in canonical path order, the source tree, the exact tag object, the Release ID,
the predecessor, the tip's successful main CI attempt and the publisher trigger;
a verifier re-renders it from the repository and the API and compares bytes.
The Sigstore subject is `platform-release.yml` on `refs/heads/main`, with the
source as workflow SHA and the recorded trigger.

Release notes carry the source and, for each fragment, its path, SHA-256 and
exact text. Past a 100,000-byte budget they list every fragment by path and
digest and leave the texts to the tag.

### What still needs the owner

Routine: merging a reviewed pull request, nothing else. A red main tip stays
unpublished until main is green again. A `RELEASE_REFUSED` line is an integrity
signal (a foreign or inexact tag, a Release that fails verification, a draft
someone else authored) and waits for an owner decision; nothing is repaired
automatically. An owner deleting a published Release is visible to the next
run's predecessor proof.

`release-backlog.yml` derives the waiting release daily, read-only, and records
it as one `deploy-assurance[release-backlog]` issue when the oldest unreleased
change is more than six hours old or the latest publisher run failed; it closes
the issue when the tip is published. The issue points at the publisher's
`RELEASE_DECISION` and `RELEASE_REFUSED` lines. That job holds `issues: write`
and nothing else; it reports and never acts.

### Closed per-merge history

v1, v2, v3 and v4 identity assets stay immutable and are verified under their
original schemas and publisher subjects. `v0.1.77` is the terminal v2 release;
`v0.1.80` is the terminal v3 release; `v0.1.94` is the terminal v4 release and
the only one a tip Release may name as its predecessor. The thirteen v4 edges
`v0.1.81` to `v0.1.93` that the retired recovery workflow published keep their
frozen window and executor pins in `platform_release_epoch.py` so their
identities still verify; the window is closed and never extended. `v0.1.41` and
`v0.1.42` are closed pre-Flux publication incidents whose annotated tags remain
immutable ledger boundaries. Tip publication never tags a historical commit and
never needs an owner-prepared tag.

## Dependency queue contract

Parallel work is a directed queue, not a shared patch-slot reservation:

- every dependent Draft PR states exact `Depends on PR #N` lines and its issue
  carries the matching native relationship;
- independent branches target `main`, use distinct issue-namespaced fragments,
  and publish their intended merge order;
- a predecessor merge triggers current-base and composed-merge checks plus
  refreshed review evidence where claims changed, but never a replacement PR
  solely because release metadata advanced. The owner may select GitHub's
  [**Update branch → Update with rebase** control](https://github.blog/changelog/2022-02-03-more-ways-to-keep-your-pull-request-branch-up-to-date/)
  to refresh the published branch; that creates a new head and invalidates all
  prior checks and receipts. Agents never invoke this owner action, rebase the
  published branch, or force-push; and
- a fresh branch/replacement PR is required only for a real semantic dependency,
  code conflict, current-main repair, unavailable/conflicting rebase update, or
  owner decision not to rewrite the PR head. Port only the residual diff.

When the supplied base is no longer an ancestor, the release gate denies with
`release head does not descend from the exact current base; request an
owner-operated GitHub rebase update or create a fresh branch` rather than a raw
Git subprocess error.

This is the queue expected for security issues blocked by #164: they may be
authored and reviewed in parallel, stay Draft while predecessors remain open,
and move one at a time under owner merge authority.

## Rollout and recovery

Issue #164 is the migration release and supplies its own fragment. Existing
Draft PRs that still edit `VERSION` or `CHANGELOG.md` must receive an additive
replacement/recut that removes those edits and adds one fragment before the new
gate can accept them. Their security implementation is otherwise independent.

A blind Git revert is deliberately insufficient: restoring the legacy gate
without its own valid legacy release transition must fail. Recovery is a
reviewed forward PR that restores the old code and simultaneously supplies the
release consequence required by the resulting head. Never move/delete a tag or
edit an immutable release to simulate rollback.
