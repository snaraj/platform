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

## Tag-derived source recovery

An owner-prepared annotated tag IS the freeze (issue #395). Everything the
retired reviewed window transcribed by hand — source, tree, first parent,
fragment path and SHA-256, the original main-CI and CodeQL run IDs, the
workflow inventory — is bound by that tag under the immutable tag ruleset and
re-derived at run time from git and the API. There is no table to edit, and no
per-edge pin: adding a backlog edge is pushing its tag.

The trust root is unchanged. The owner prepares every release tag with the
owner's own credentials, the tag ruleset is immutable with no bypass, and a
derived edge is refused unless every derived fact re-verifies at run time:

- **git-derived** (`scripts/ci/release_backlog.py`, `Edge` and
  `published_edges`; `platform_release_contract.py`,
  `discover_transition_window` and `validate_tag_record`): the ledger walk
  proves each tag's tagger identity, instant and exact message, one contiguous
  first-parent chain, and exactly one changelog fragment per adjacent edge. A
  tag on a merge commit, on a commit main only reached through a merge, on a
  commit past `--head`, skipping or duplicating a fragment, or leaving a gap in
  the patch sequence refuses there.
- **API-derived** (bounded GET-only `PublicAPI`): for each pending edge, the
  listing for `head_sha=<source>, branch=main, event=push` must hold exactly
  one run of `pull-request.yml` and one of `codeql.yml`, each concluded
  `success` on its latest attempt — the same attempt the ordinary publisher
  consumes, because `workflow_run` fires on the completed attempt. That is
  parity with the ordinary path rather than a relaxation: `prove_ci` still
  builds the required-jobs receipt with `build_main_ci_jobs_receipt`, the same
  function `verify-platform-release-main-jobs.sh` runs for an ordinary release.
- **workflow digests**: the three workflow blob digests of the source tree are
  recorded per edge in the selection for audit. They are informational. The tag
  binds the commit and the commit binds the tree that contains those blobs, and
  the behavioural control is the required-jobs receipt above.

### The executor relation

An ordinary publication runs at the commit it releases, so `execution.source_sha`
equals `source.merge_sha`. A recovery publication runs behind main, so its
executor is a STRICT first-parent descendant of the edge's source and is itself
on protected main's own first-parent line (or is its tip). BOTH halves are
first-parent membership rather than reachability, deliberately: a commit main
absorbed through a merge is an ancestor of main without ever having been main,
so `merge-base --is-ancestor` alone would admit a source, or an executor, that
no protected-main dispatch ever ran at. That relation replaces the membership
refusal and the per-edge executor pins: one executor drains many edges and later
becomes a source itself, which is the ordinary case rather than a replay. A
replay of an old workflow is refused by construction, because every earlier
source is an ancestor of the executor rather than a first-parent descendant of
it, and the terminal `v0.1.80` source precedes every v4 source. `validate_execution` is git-free and
refuses recovery-shaped evidence that arrives without an ancestry proof; the
caller proves it with `platform_release_contract.executor_descends` against the
checkout, which is pinned to current protected main.

New v4 identity assets keep original source/main-CI fields separate from
`execution.source_sha`, `execution.tree_sha`, `execution.main_ci` and the actual
publisher run. The signing subject follows that relation, not the tag number:
an identity whose recorded `publisher_workflow` or `publisher_event` disagrees
with its own executor relation is refused. The v1/v2/v3 schemas and existing
immutable bytes are unchanged.

### What one dispatch proves

`prepare` walks the ledger in git, then proves with the API: the terminal v0.1.80
checkpoint, the predecessor Release of the first pending edge in full, and each
pending edge's owner-prepared tag and original CI. It does NOT re-prove the
published edges in between. They are immutable, each was proved by this same
reader as the predecessor at its own publication, and the ordinary publisher
proves only its predecessor — so the per-run bounds are `FIXED + PER_EDGE x
pending` and never grow with the number of releases already published. That is
the issue #393 outage class removed rather than deferred; `per_run_bounds` and
`selection_bytes` in `platform_release_recovery.py` state the measured costs
they derive from, and both remain hard caps enforced on every read.

`prepare` also refuses, by name, while a `platform-release.yml` run is queued or
in progress: that closes the race between the tip merge's own publisher and the
drain by construction.

The ordinary publisher reaches the same relation from the other side. The first
ordinary release after a drain has a RECOVERY publication as its predecessor,
so `wait-platform-release-predecessor.sh` hands its own full-depth checkout to
the identity validators; without it the epoch policy would refuse that
predecessor for want of an ancestry proof and the ordinary path would stall
exactly where the backlog ended.

The `immutable-settings` job re-verifies the whole selection and proves the
immutable-release repository setting ONCE per dispatch. The setting is
repository-level and the Administration-read App token never crosses into the
write job; a per-edge re-proof would put that token into `publish`, which is a
permission expansion rather than a stronger control.

The scan runs newest-first and stops at the first published Release, so a
Release missing BELOW a present one is not what it looks for. That state cannot
arise while the controls hold: a Release is immutable, and the publisher proves
its predecessor exact before it writes, so `v0.1.N` existing is itself evidence
that `v0.1.N-1` existed when it was published. Only an owner deleting a
published immutable Release could produce it, and the drain would then simply
report the backlog above the hole; the hole is repaired by the owner, and the
full `prove_release` of the predecessor still re-verifies that Release's own
signed predecessor tag and peeled commit, so the chain is checked one link
further back on every run.

`publish` then loops in list order: per edge `bind` (env rebound exactly as for
an ordinary release), publish, and an independent `readback` of the new Release
— immutable, non-draft, two assets, canonical identity, Sigstore subject and
executor record. The first refusal stops the run; nothing is skipped. A
zero-asset draft resumes on the next dispatch; a partial draft stays an owner
delete. `prove_context`'s executor-equals-current-main check runs inside every
write boundary, so a merge landing mid-drain stops the loop at the next edge
rather than publishing against a main the executor no longer is.

After owner preparation of the exact annotated tag, recovery creates a draft
with only `tag_name`, `name`, `body`, `draft:true` and `prerelease:false`. It
omits `target_commitish` and requires GitHub's returned default-target hint to
be exactly `main`; the tag object and peeled commit bind the source. The notes
PATCH contains only `body`; the publish PATCH contains only the selected
`tag_name` and `draft:false`. A staged record may expose the canonical tag or
GitHub's temporary `untagged-<20 hex>` tag matching both staged asset URL
tokens. Before and after each Release or asset write, the publisher rechecks the
unchanged tag object, source, predecessor and selected executor, and every
refusal names the check that refused. Partial assets, foreign custody, a moved
tag, a missing settings proof or a permission refusal stop delivery.
No token-scope expansion or automatic tag fallback is permitted.

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
owner the API actor; the annotation claims no bot action and no signed tag. The
message is accepted in exactly the two encodings git produces for it — the
publisher's unterminated form and `git tag -a -m`'s single trailing newline —
nothing looser. `--head` still defaults to `origin/main`: with no frozen window
there is nothing to pin the head to, so the tip merge's own edge gets its tag
and drains in the same dispatch.

### Draining the published backlog

Three steps, whatever the length of the backlog:

1. Confirm no publisher run is in flight (`prepare` refuses by name if one is,
   so this is a courtesy check rather than a control):

   ```
   gh run list --workflow platform-release.yml --branch main --limit 1
   ```

2. Prepare every missing tag:

   ```
   python3 -I -B scripts/prepare_recovery_tags.py --repository . --head origin/main --push
   ```

3. Dispatch the recovery ONCE and read it back:

   ```
   gh workflow run platform-release-recovery.yml --ref main && gh run watch "$(gh run list --workflow platform-release-recovery.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
   ```

The run log names every edge: one `RECOVERY_EDGE tag=... source=... reads=...
seconds=... decision=published|refused:<reason>` line per edge and one
`RECOVERY_SUMMARY pending=N published=M ...` line for the run. A non-201 asset
upload prints its HTTP status and a bounded slice of the response body, and each
write-boundary refusal names the check that refused; the two mute failures of
2026-09-22/23 (the v0.1.93 upload and the v0.1.89 OIDC transient) are reproduced
as tests against a fake API.

A lost dispatch response requires readback of matching runs, never a duplicate
POST. Only completed success makes an edge a predecessor. When the backlog is
complete the reader refuses with `the source backlog is complete; use the
ordinary publisher`, which is the expected answer on a healthy repository.

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
actions write, no App token, no secret — it reports and never acts, and its own
review bounds (`MAX_PLAN_EDGES`, `MAX_UNRELEASED_LOOKBACK`, `MAX_REQUESTS`)
stay exactly as they are.

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
