# Platform repository identity transition

The existing repository becomes `platform`, retaining its GitHub object,
protected history, Releases, settings, and review record. A later
`platform-k8s-infra` repository will own application GitOps composition.
Application repositories continue to own their charts and images.

This runbook covers the release compatibility boundary. It does not perform
the repository rename, extraction, Flux source change, or live cleanup.

## Closed release epochs

The policy in [`platform_release_epoch.py`](../../scripts/ci/platform_release_epoch.py)
starts from the verified immutable `v0.1.68` checkpoint. The existing annotated
tag ledger still derives the next patch; no agent assigns or creates a tag.

| Release edge | Signed source identity | Signature subject and assets |
| --- | --- | --- |
| Checkpoint to its exact next release | Terminal v1, `snaraj/website-infrastructure` | Existing publisher subject and v1 JSON/bundle names |
| Terminal v1 to its exact next release | First v2, `snaraj/platform` | New publisher subject and v2 JSON/bundle names |
| Later exact-next releases | v2, `snaraj/platform` | New publisher subject and v2 JSON/bundle names |

Publication under the old name is limited to that terminal edge and its exact
checkpoint SHA. Publication under the new name requires the original immutable
GitHub repository ID. Both the workflow context and a fresh REST repository
record must agree. A renamed or replacement repository cannot qualify merely
by occupying one of the allowed names.

Historical v1 JSON bytes and the v1 schema stay unchanged. The terminal v1
payload's existing fields bind its eventual protected-main SHA, tree, release
ID, tag object, predecessor, and exact workflow attempts. The policy therefore
needs no predicted hash of the commit that introduces it. V2 additionally signs
the repository object ID.

The expected external release tag chooses the schema, asset names, and Sigstore
subject. Downloaded content cannot select its own trust root. After a rename,
GitHub may report the new repository name in old release URLs and run metadata;
that transport alias requires proof of the same repository object, while the
signed historical name stays unchanged. Exact asset IDs, bytes, hashes, tag
objects, source trees, and workflow attempts remain mandatory.

## Frozen selector lineage

Application GitOps already follows protected `main`; the legacy selector is
suspended. Source publication now carries the previously verified selector
digest and build SHA, pinned in the epoch policy. It refuses changes to the
selector's build inputs relative to that build, even across several releases.
The legacy image name and its old signing/attestation subject remain intact in
both schemas.

The publisher has no package-write permission, image builder, registry login,
or image signing path. It validates the predecessor's canonical identity,
Sigstore signature, tag, and exact successful workflow attempts before any
source publication. This replaces duplicate workflow-side verification without
removing the transaction's checks.

The installed selector, its old package, the v1 schema, and recovery verification
remain available. Removing installed resources requires separate evidence of
quiescence and a reviewed recovery decision. Never resume a v1-only selector
against v2 releases as part of a repository rename.

## Integration sequence

1. Merge the compatibility PR through the ordinary owner-only merge path.
   Verify the derived terminal-v1 release with the
   [source release runbook](platform-source-releases.md): successful exact-SHA
   CI/publisher attempts, annotated tag, immutable Release, canonical bytes,
   and the old Sigstore publisher subject. Finish this before another merge.
2. Rename the existing repository object. Do not create a replacement under
   the destination name or reuse the old name for another project.
3. Re-read the repository ID and default branch, protected-main and tag
   rulesets, immutable-release settings, merge restrictions, Actions defaults,
   and existing App installation selection. Preserve the same permissions;
   a failed check stops the transition. GitHub redirects are routing behavior,
   not identity evidence.
4. Update local origin URLs and explicitly select the new repository in
   delivery commands: `ready_check.py --repo snaraj/platform` and
   `promote_releases.py --github-repository snaraj/platform <command>`.
   Generated scheduler configuration carries that explicit selection. Local
   reviewer-App tooling must also verify the renamed original object before
   use. Updating configuration does not start a contained process.
5. Prepare and review the next source change under the new repository name.
   After owner merge, verify the first v2 source release and its exact signed
   terminal-v1 predecessor. The new source publisher subject is
   `https://github.com/snaraj/platform/.github/workflows/platform-release.yml@refs/heads/main`;
   the assets are `platform-release-identity.v2.json` and its
   `.sigstore.json` bundle. A successful old-subject verification is insufficient.
6. Handle the Flux source URL, repository extraction, and installed-resource
   cleanup in separate reviewed changes, with current operational evidence.
   Preserve installed hard controls throughout. Source publication is not
   evidence of cluster convergence.

## Failure and rollback

Unknown names, object substitution, an unexpected predecessor, selector drift,
partial Releases, and signature failures stop publication. After the terminal
v1 edge, further publication under the old name is intentionally denied.

Before the first v2 publication, an additive reviewed correction can revise the
transition policy if the rename must be abandoned. The correction must
explicitly restore a valid exact-next publication edge; a name redirect or an
old workflow rerun is not a rollback. Once v2 is published, repair forward
within v2 and preserve immutable historical evidence. Never rewrite tags,
Releases, or signed payloads to make them display the new name.
