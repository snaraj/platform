# Issue 195 chart acquisition receipt

Captured 2026-09-07 for issues #331/#332, which advanced lidersea.com to
`0.1.42` and advanced naranjo.online to `0.1.80`; it supersedes the issues
#320 capture of 2026-09-05. The canonical, machine-checked record is
`195-chart-acquisition-receipt.json`; this Markdown is its explanatory view
and must not be used as an independent source of release pins. This receipt
is public, credential-free evidence for the exact chart artifacts committed
by this repository. It is acquisition evidence, not proof of Flux or live
cluster convergence.

The acquisition was run by `scripts/promote_releases.py` with Cosign 3.1.3,
the exact `versions.env` pin; registry reads were direct anonymous OCI API
resolutions whose `docker-content-digest` answers were required to agree with
the fetched manifest bytes' own hashes (the technique reviewed in PRs #255 and
#259), with ORAS 1.3.4 remaining the pinned acquisition tool of record.
Each human tag was resolved, the resulting repository-at-digest was
verified against the exact publisher identity and GitHub Actions issuer, the
Helm layer was fetched by its own digest and inspected, and both chart and
embedded workload tags were resolved a second time. Both pairs of resolutions
agreed. The immutable Release asset and protected-main source commit were
also bound for each acquisition. Public SLSA v1 attestations bound the exact
workload indexes; chart trust remains each chart's exact Cosign signature.

| workload and canonical chart repository | tag | OCI manifest / config / chart-layer digests | Chart.yaml identity | embedded workload image | Linux ARM64 child |
| --- | --- | --- | --- | --- | --- |
| lidersea.com — `ghcr.io/snaraj/charts/lidersea-com` | `0.1.42` | `sha256:5a944c4602cd1b1df8b6613bc2daa037dcc00b2616402de33e5eece1edd8cdf7` / `sha256:9f9bc51575f980940cb8562e6b50d0ac078a560b9cc67678b0169895d3747c16` / `sha256:7497364e68af0f909625735bb1b7fe64120fd6920a2ff0e16dcefd9ebe352d99` | name/version/appVersion `lidersea-com` / `0.1.42` / `0.1.42` | `ghcr.io/snaraj/lidersea-com:v0.1.42@sha256:d23a20d3c222f7acb7e3a5e2391767eb5762dae3865eb1546b809d0811b8abc9` | `sha256:f424768e07081d7f8fd85f0ea05e3e1e85421d62de27fe08109193a3813b0de9` |
| naranjo.online — `ghcr.io/snaraj/charts/naranjo-online` | `0.1.80` | `sha256:a665c74985b0dc3e9b8351c0306d58f8d318a581f7fdda71874a98fde85773f3` / `sha256:c3c21cbc2b029703ef13dda2818d296282ad0ca8f3df65bc424fe81998622c4f` / `sha256:c9a3ee1272562dd7ab38d3ab834e491f8c689a799ee33eec56fa3fc9937ebe7f` | name/version/appVersion `naranjo-online` / `0.1.80` / `0.1.80` | `ghcr.io/snaraj/naranjo-online:v0.1.80@sha256:63236d492c84e7d0e48f3e8b8c1b7551053defbd6461e27a3b3e6e5c1559f05f` | `sha256:6e3c2d23ad04a61aa22d3c123802922c4d1360e8ca10c0635fe3511ad94ac786` |

Publisher Release bindings:

- lidersea.com: protected-main source `ff25643033f89996b32826a3ac02d0bee9074536`; immutable Release asset `sha256:b6e90ea1ff09854fae7319af3741ff5640ae3da8a2a7e4937d041b68fda30422`.
- naranjo.online: protected-main source `6ce0887c38b5f70ceff7d75f3cc1a91dd6947093`; immutable Release asset `sha256:61825308c6290fb46f38b58c92c451b1c826b0474ca98ce911f7785ac3a0c135`.

Each `vX.Y.Z` annotated tag was dereferenced to the commit above, and that
same commit is what the Release asset's own `source_sha` field reports — two
independent statements of the source binding that had to agree. Each manifest
also states the chart and image digests independently of the registry
resolution, and both agreed.

Each signed OCI manifest contained exactly one layer with
`application/vnd.cncf.helm.chart.content.v1.tar+gzip`; the layer selector
copies exactly that single matching layer.

Cosign accepted only these certificate subjects, with issuer
`https://token.actions.githubusercontent.com`:

- `https://github.com/snaraj/lidersea.com/.github/workflows/release-publisher.yml@refs/heads/main`
- `https://github.com/snaraj/naranjo.online/.github/workflows/release-publisher.yml@refs/heads/main`

Exact-layer inspection hashes provide a reproducible custody check:

- lidersea `Chart.yaml`: `sha256:381af60b25e001bf2f8d3d79d67379dca3accb307f885b6e54d5c590e224de6c`
- lidersea `values.yaml`: `sha256:980b76e70e057291b69f12878586aaaf25364110985ffdedc575370980466844`
- naranjo `Chart.yaml`: `sha256:022e0fa6ff7ca083089f4a2c29b2cba8dd7be6bfdc525148da9a67c77ec3afda`
- naranjo `values.yaml`: `sha256:1a6e06f53bf77120a37994c8eed1491b9005d843ff30dadd381b30389df55b5c`

Future updates repeat this exact sequence: resolve the reviewed tag, verify the
exact manifest, config, sole layer and signer, inspect chart identity and
embedded workload image, bind the protected source and immutable Release
asset, resolve the tag again, then atomically review the audit annotation and
digest. Tag movement, deletion, or replacement after that point cannot change
the bytes selected by the committed digest.
