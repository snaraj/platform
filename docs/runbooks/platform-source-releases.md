# Platform source releases and dependency queue

## Scope and authority

This runbook implements issue #164. It changes source-release bookkeeping only:
it grants no merge, tag, live-system, provider, cluster, deployment, or settings
authority. The owner alone merges. GitHub Actions may create only the annotated
platform source tag and immutable Release with its exact signed identity asset
pair after the protected-main checks and settings proofs pass. `v0.1.40` is the
sole zero-asset transition predecessor; it is never the format for a new
release.

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
multi-commit range; the final main SHA is always the release identity.

## Tag-derived transaction

The immutable `v0.1.9` tag and its exact source SHA are the migration floor.
Legacy gaps before that floor remain historical and cannot influence new patch
allocation. From the floor forward, the contract requires every platform tag to
be canonical `vX.Y.Z`, annotated with the exact embedded name, source-bound
message, GitHub Actions bot identity, and source-commit date, exactly one patch
after its predecessor, and on one merge-free ancestral sequence. Every adjacent
post-floor tag boundary must also add exactly one valid fragment; a misplaced
tag can never consume two release intents or hide an earlier one.
The validator refuses more than 1024 platform tag refs before performing the
adjacent-edge walk, so a corrupt or unbounded inventory cannot consume the
entire 30-minute publication window.

For an untagged successful main SHA, the publisher:

1. fetches public tags without persisted checkout credentials;
2. validates the complete post-floor ledger;
3. requires the latest tag and immutable Release to be exact, consuming the
   canonical identity asset pair after the one-time `v0.1.40` bridge, except
   for the exact burned `v0.1.42` to `v0.1.43` recovery described below;
4. requires exactly one newly added fragment since that predecessor;
5. derives `next = latest patch + 1` without reading `VERSION`;
6. renders deterministic notes containing the source SHA, fragment path,
   fragment SHA-256, and exact fragment Markdown; and
7. reuses, resumes, or creates only the exact annotated tag, canonical identity
   JSON, detached Sigstore bundle, and immutable Release through the existing
   closed REST transaction.

The bounded GET-only predecessor wait finishes before the short-lived
Administration-read token is minted. The immutable-release setting is therefore
proved after ordering and immediately before the write job. That job rebinds the
window once and revalidates the exact predecessor tag and Release before every
mutation boundary; renewed pending, absent, mutable, or foreign state fails.

`v0.1.41` and `v0.1.42` are closed pre-Flux publication incidents. Their exact
annotated tags remain immutable ledger boundaries. The sole `v0.1.42` to `v0.1.43` edge may
observe the predecessor Release as absent. In the write job only, the publisher
enumerates the complete authenticated Release inventory, accepts either the
exact known signed two-asset `v0.1.42` draft or its clean absence, validates its
source, tag object, tree, workflow attempts, asset IDs, bytes, digests, signature,
and shared staged download token, then deletes only that exact draft Release ID.
It proves both draft absence and the unchanged annotated tag before creating
`v0.1.43`. The successor still requires fresh protected-main CI, a new exact
annotated tag, two signed identity assets, and an immutable published Release.
Every later edge returns to the ordinary complete-predecessor rule.

Historical v1, v2 and v3 identity assets remain immutable and are verified under
their original schemas and publisher subjects. `v0.1.77` is the terminal v2
release. Its exact successor begins v3, whose signed identity records only the
platform source, repository object, predecessor, tag, immutable Release and
successful workflow attempts. Application selections live in
`snaraj/platform-k8s-infra`; v3 therefore carries no selector or site payload.

An exact existing tag at the source is an idempotent replay. A lightweight,
skipped, reversed, moved, foreign, or non-ancestral tag; a missing earlier tag;
or a tag/Release metadata mismatch is burned/conflicting state and fails.

## Rapid merges

Publisher workflows keep exact-SHA concurrency identities. If main SHAs A, B,
and C arrive before A is published, A sees one fragment and may publish; B sees two
and returns the distinct pending status; C sees three and does the same. Each
later workflow fetches tags and retries only that pending status. Once A's exact
tag and immutable Release both exist, B derives the next patch; once B is exact,
C does. Outside the exact burned `v0.1.42` recovery edge, a tag without its
exact Release remains pending and cannot allocate the next patch. Unsafe ledger
states are never retried as contention. A bounded timeout fails the workflow
without allocating or moving a tag. For historical v1/v2/v3 execution, the exact
SHA can be rerun normally. Ordinary v4 additionally requires the workflow SHA,
execution SHA and released source SHA to agree. A later main merge can make
the `workflow_run` context differ from the earlier source; that publication
fails closed even if its source CI succeeded. Keep main at the intended
executor while completing the recovery below and its ordinary successor.
This repair does not authorize a general replay of later sources. If main
advances and equality cannot be restored without changing immutable history,
stop delivery for a separately reviewed forward repair.

Within that bounded wait, the expensive ledger result is cached only while the
complete `refs/tags/v*` ref name, tag-object ID, and peeled target snapshot is
byte-identical. A created, retargeted, or replaced tag changes the key and forces
full validation before the next REST read. A Release-only state change leaves
the validated Git ledger unchanged and repeats only the exact GET classifiers.

## Finite historical-source recovery

Issue #369 admitted the first three consecutive protected-main sources after
the immutable `v0.1.80` checkpoint; issue #317 freezes the eight the stalled
publisher left behind, ending at the last merge before that change, issue #391
freezes the twelfth, the merge that repaired the backlog derivation, and issue
#393 freezes the thirteenth, the merge that derives the reader's per-run bounds
from this list, because each change moves main past its predecessor. The window
is a reviewed list and never a computed range: adding an edge is a reviewed
commit, so CI can never widen it. The ledger derives their next patches; the table does not allocate
tags. Both original workflow attempts must still be completed and successful,
and every original workflow file, tree, parent and fragment must match the
frozen policy in `platform_release_epoch.py`. The window spans two publisher
revisions and three CodeQL pins, so each edge names one exact, complete
workflow inventory there rather than sharing a single fingerprint.

| Source | Original main CI / CodeQL (attempt 1) | Fragment |
| --- | --- | --- |
| `060c9678e130487b27cdaec395b0f1c5d74b9240` | `34283118915` / `34283118636` | `362-obsync-private-boundary.md` |
| `9cd79f1e69cfa00eb5467822831056101629c8f8` | `34305321734` / `34305321809` | `365-obsync-staged-readiness.md` |
| `3b7a0532ba5fe2f10037023f3e26ec5876f8d191` | `34638257426` / `34638258315` | `367-reserved-file-storage.md` |
| `bb9a8d7a45f761491a4e17fffdc79a22e87c6dd4` | `34661250611` / `34661250547` | `369-source-recovery.md` |
| `47fc0a1fb573983d69acfc88bcf6f950899f8772` | `34667651399` / `34667651395` | `373-reserved-evidence.md` |
| `2ad053e307e43f6dfb5015de1f1bf09c3505a832` | `34673797428` / `34673797429` | `371-owner-prepared-recovery-tags.md` |
| `57a8807d551f19b13ee9e2caea398dbaa280296f` | `34732230714` / `34732230710` | `377-private-connector-artifact.md` |
| `64cc95f3802c8feb8567f9b607aeac5c10d8d830` | `34789838965` / `34789838936` | `379-release-draft-tags.md` |
| `2a597ce999979ae463bc575eb63d6d7d5a2a182d` | `34932536836` / `34932536855` | `381-codeql-4-38.md` |
| `54ac82e692fa11999fafde52f2f4fe6ea17b47b5` | `35548047591` / `35548047644` | `383-boot-time-recovery.md` |
| `10ee0a67144675630456daafeb002755aba653d4` | `35684876122` / `35684876102` | `387-codeql-4-38-1.md` |
| `f71fc1f37f9ca1883e10286a13132cd70a17cf9f` | `35773664240` / `35773664214` | `317-release-backlog-automation.md` |
| `76f60b306d028f5a2febcbf7b35c8ab16b0dd139` | `35788330613` / `35788330655` | `391-frozen-executor-pin.md` |

A row whose Release already exists and whose executor this window later froze
as a source also carries that executor as `executor_sha`, recorded in
`PINNED_EXECUTIONS` beside the Release ID it was read from. Those pins, and
nothing else, are what keep an already published edge out of the membership
refusal below; an edge no publisher has taken yet has no executor to pin.

| Published edge | Release | Executor pinned |
| --- | --- | --- |
| `v0.1.81` | `387789735` | `10ee0a67` |
| `v0.1.82` | `394156049` | `76f60b30` |
| `v0.1.83` | `394157866` | `76f60b30` |
| `v0.1.84` | `394159524` | `76f60b30` |
| `v0.1.85` | `394161048` | `76f60b30` |
| `v0.1.86` | `394162468` | `76f60b30` |
| `v0.1.87` | `394164673` | `76f60b30` |
| `v0.1.88` | `394166552` | `76f60b30` |
| `v0.1.89` | `394168254` | `76f60b30` |

The current protected checkout executes the repair; the historical trees are
data. A no-input `platform-release-recovery.yml` dispatch selects the oldest
incomplete edge once and binds its source, tag, predecessor, executor, repository
object, run ID, attempt and executor CI in a canonical receipt. Every later job
rechecks that receipt, original source CI, successful current-executor main CI
and CodeQL, the current main ref, and the complete immutable predecessor. A fresh
dispatch cannot overtake a still-running original publisher; only attempt 1 is
admitted, no rerun borrows an earlier attestation or selection, and dispatches
share one non-canceling concurrency group.

New v4 identity assets keep original source/main-CI fields separate from
`execution.source_sha`, `execution.tree_sha`, `execution.main_ci` and the actual
publisher run. The external tag policy selects the recovery signing subject
only for those thirteen exact edges. Later ordinary releases use the ordinary
subject and require source/executor equality; downloaded identity fields cannot
select another trust root. The v1/v2/v3 schemas and existing immutable bytes are
unchanged. Source CI and publisher attempts are verified through exact
attempt-specific API records, including the original attempts named by the
terminal checkpoint.

After owner preparation of the exact annotated tag, recovery creates a draft with only
`tag_name`, `name`, `body`, `draft:true` and `prerelease:false`. It omits
`target_commitish` and requires GitHub's returned default-target hint to be
exactly `main`; the tag object and peeled commit bind the historical source.
The notes PATCH contains only `body`; the publish PATCH contains only the
selected `tag_name` and `draft:false`, with no `target_commitish`. A staged
record may expose the canonical tag or GitHub's temporary `untagged-<20 hex>`
tag matching both staged asset URL tokens. The signed intended tag and exact
annotated object remain fixed; final immutable validation accepts only that
canonical tag and its final asset URLs. Before and after each Release or asset write, the publisher
rechecks the unchanged tag object, source, predecessor and selected executor.
An exact zero-asset draft may resume on a fresh dispatch. Partial assets,
foreign custody, a moved tag, a missing settings proof or permission refusal
stop delivery. No token-scope expansion or automatic tag fallback is permitted.

### Owner-prepared historical tags

Only the owner may prepare the next exact annotated tag, and only with the
owner's own credentials: CI never creates one (issue #375).
Agents never create tag objects or refs.
The owner must not create the Release or its assets.
One command derives every missing tag from the immutable ledger and prepares it:

```
python3 -I -B scripts/prepare_recovery_tags.py --repository . --head origin/main --push
```

Without `--push` it prints the plan and writes nothing; it refuses inside a
hosted runner; it accepts only a `--head` that `refs/remotes/<remote>/main`
already contains; and it refuses rather than repairing when the ledger or a
present tag disagrees. Before pushing any ref it proves, through the publisher's
own validators, the ledger-derived target, the release-tagger identity, the
source commit's committer instant and the exact `Platform release <tag> from
<source>` message, then re-walks the complete post-floor ledger. It never
deletes, moves or force-updates a ref, never touches a Release, and leaves the
owner the API actor; the annotation claims no bot action and no signed tag.
Preparing every missing tag in one run is no general tag-creation exception; the
published backlog is still drained one edge at a time below. The message is
accepted in exactly the two encodings git produces for it — the publisher's
unterminated form and `git tag -a -m`'s single trailing newline — nothing
looser. The finite issue #369 edges, ledger-derived and never allocated by this
table:

| Tag | Historical source |
|---|---|
| `v0.1.81` | `060c9678e130487b27cdaec395b0f1c5d74b9240` |
| `v0.1.82` | `9cd79f1e69cfa00eb5467822831056101629c8f8` |
| `v0.1.83` | `3b7a0532ba5fe2f10037023f3e26ec5876f8d191` |
| `v0.1.84` | `bb9a8d7a45f761491a4e17fffdc79a22e87c6dd4` |
| `v0.1.85` | `47fc0a1fb573983d69acfc88bcf6f950899f8772` |
| `v0.1.86` | `2ad053e307e43f6dfb5015de1f1bf09c3505a832` |
| `v0.1.87` | `57a8807d551f19b13ee9e2caea398dbaa280296f` |
| `v0.1.88` | `64cc95f3802c8feb8567f9b607aeac5c10d8d830` |
| `v0.1.89` | `2a597ce999979ae463bc575eb63d6d7d5a2a182d` |
| `v0.1.90` | `54ac82e692fa11999fafde52f2f4fe6ea17b47b5` |
| `v0.1.91` | `10ee0a67144675630456daafeb002755aba653d4` |
| `v0.1.92` | `f71fc1f37f9ca1883e10286a13132cd70a17cf9f` |
| `v0.1.93` | `76f60b306d028f5a2febcbf7b35c8ab16b0dd139` |

### Draining the published backlog

After owner merge and successful exact-executor main CI and CodeQL, keep main at
that executor, confirm no publisher proof is in flight, prepare the missing tags
above, and never rerun a frozen old workflow. One executor drains many edges —
the merge that froze `v0.1.92`, `76f60b30`, published eight of them, `v0.1.82`
through `v0.1.89` — so when an executor is itself frozen as a source later, the
pull request that freezes it pins EVERY edge it published: each edge carries the
`executor_sha` its own already published immutable identity records, alongside
the re-baselined exact-table tripwire and window fingerprint, in that one pull
request. This is not a courtesy to the edge that prompted the change: an
unpinned published edge is refused as a foreign executor, and the drain stops
there, so pinning one and leaving its siblings only moves the outage. Every
published edge's identity asset is committed under
`tests/security/fixtures_release_identity/` and validated against the new
window by the class guard in `tests/security/test_platform_release_v4.py`,
offline, before that pull request is reviewed. Then dispatch once per edge:

```
gh workflow run platform-release-recovery.yml --ref main && gh run watch "$(gh run list --workflow platform-release-recovery.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
```

Every dispatch re-proves each published edge, so the reader's per-run bounds
scale with the window instead of being fixed beside it: `per_run_bounds` in
`platform_release_recovery.py` derives the read budget from the frozen window's
length, states the measured per-edge and fixed costs it is derived from, and
refuses a window the deadline could not walk. Extending the window re-derives
both bounds, and the pull request that extends it proves they still hold for a
fully published window (issue #393).

A lost dispatch response requires readback of matching runs, never a duplicate
POST. After each, independently read back the annotated tag, the immutable
non-draft/non-prerelease Release and its two assets — size/digest/canonical
identity, Sigstore subject, issuer, actual executor SHA/event, every signed
original attempt. Only completed success makes an edge a predecessor. When the
window is complete, let the repair's own ordinary publisher finish, or rerun
that whole workflow (never failed-jobs-only) if its wait timed out. After the
issue #393 repair merges, that is: nothing to prepare, because every pending
tag from `v0.1.90` to `v0.1.93` already exists; keep main at that executor,
drain `v0.1.90` through `v0.1.93` one dispatch at a time, then let that merge's
own publisher — rerun whole if it timed out — publish `v0.1.94`.

A publisher that died mid-upload leaves a draft with a stale identity asset pair
and recovery refuses `draft Release asset inventory count is not exact`. Deleting
those two assets stays an owner step: that shape is also the legitimate staged
state immediately before publication.

```
gh api "repos/snaraj/platform/releases/<draft id>/assets" --jq '.[].id' | xargs -I{} gh api -X DELETE "repos/snaraj/platform/releases/assets/{}"
```

`release-backlog.yml` derives this same backlog daily, read-only, and records it
as one `deploy-assurance[release-backlog]` issue carrying the pending count, the
oldest pending source and the command above, closing it when the backlog clears.
That job holds `issues: write` and nothing else — no contents, id-token or
actions write, no App token, no secret — it reports and never acts.

An immutable asset may become visible before its original publisher finishes.
A reader waits for that exact attempt; a failed, cancelled, missing or unknown
original attempt is a terminal delivery hold. A later successful dispatch or
rerun cannot replace the signed attempt or rewrite immutable bytes. This scope
has no settlement-proof extension. Local modeled pass/deny checks and review
permit source Ready; the first protected execution proves actual ordinary-token
provider capability. No source release implies storage qualification, live
deployment, application promotion or device acceptance.

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
