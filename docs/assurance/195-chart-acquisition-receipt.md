# Issue 195 chart acquisition receipt

Captured 2026-09-06 for issues #331/#332, which advanced lidersea.com to
`0.1.42` and advanced naranjo.online to `0.1.77`; it supersedes the issues
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
#259), with ORAS 1.3.3 remaining the pinned acquisition tool of record.
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
| naranjo.online — `ghcr.io/snaraj/charts/naranjo-online` | `0.1.77` | `sha256:04d584000b998903cdc116b7c79517505870dc47c72af8934db59b29008129d1` / `sha256:2c90ca3c8e6422c92189c14719c8f7332f99d7898a223ce67d92db980b10553e` / `sha256:81ad1493529cb84d2129f1d4c71df3c14d944019bba0b372115e2ce5b2644ef0` | name/version/appVersion `naranjo-online` / `0.1.77` / `0.1.77` | `ghcr.io/snaraj/naranjo-online:v0.1.77@sha256:cbe54d2943640e71b927e0c40e8512ec81de5266339c3a50413cbd3f47240971` | `sha256:382588655ee0ffcb62737672544c731f1d3f40f749e591b0a9a84d097ab1d5fb` |

Publisher Release bindings:

- lidersea.com: protected-main source `ff25643033f89996b32826a3ac02d0bee9074536`; immutable Release asset `sha256:b6e90ea1ff09854fae7319af3741ff5640ae3da8a2a7e4937d041b68fda30422`.
- naranjo.online: protected-main source `d64b63addaec320aaeb0565cc65ae38ad37c72a3`; immutable Release asset `sha256:d48254d845e4f0e6285a81f06026da4c067982f7d7286567bcb26df33f77d141`.

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
- naranjo `Chart.yaml`: `sha256:62dffd028ecba410345a6428352ffe054163405b9604bfd9edda4418021500be`
- naranjo `values.yaml`: `sha256:b3729e72366baa1d3fb7907c4a841f0e778c05c3a4e597cc883ddd8a7c8d7344`

Future updates repeat this exact sequence: resolve the reviewed tag, verify the
exact manifest, config, sole layer and signer, inspect chart identity and
embedded workload image, bind the protected source and immutable Release
asset, resolve the tag again, then atomically review the audit annotation and
digest. Tag movement, deletion, or replacement after that point cannot change
the bytes selected by the committed digest.
