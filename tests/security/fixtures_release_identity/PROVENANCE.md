# Published release-identity fixtures — provenance

Each file here is the **immutable asset itself**, byte for byte, downloaded
from its Release as `platform-release-identity.v4.json`. Nothing was edited:
the class guard asserts every digest below, so an edited copy fails there
first. Each digest is the one the REST release record reports for that asset.

| Fixture | Release | Bytes | sha256 | Executor recorded |
| --- | --- | --- | --- | --- |
| `v0.1.81-platform-release-identity.v4.json` | `387789735` | 1614 | `4e9cfb1bdbdd27cf8fac42905f5832e3f24a5a24fe2c6636cf63cdabb95db119` | `10ee0a67` |
| `v0.1.82-platform-release-identity.v4.json` | `394156049` | 1614 | `dab21ffeddb00f7220752f69cc11e4f9154e4fbe85c430fafcaac53020647948` | `76f60b30` |
| `v0.1.83-platform-release-identity.v4.json` | `394157866` | 1612 | `6b19aeeadd85e3ade3dc1a6c2f6eab1377d540708ec8862a890a4102476a5474` | `76f60b30` |
| `v0.1.84-platform-release-identity.v4.json` | `394159524` | 1606 | `dead16cd692680fdeb32bcd921e1de0b5045e195a414fec4e9f3cb89e87c61b2` | `76f60b30` |
| `v0.1.85-platform-release-identity.v4.json` | `394161048` | 1608 | `fd8835b2e140b41c11c0e4b2069b2ce2dc98de9b680579201aaa663850bc8d26` | `76f60b30` |
| `v0.1.86-platform-release-identity.v4.json` | `394162468` | 1619 | `d807ca4563da58aae418b9d77feadbd0de175f7c84de92852f6d3d651002682b` | `76f60b30` |
| `v0.1.87-platform-release-identity.v4.json` | `394164673` | 1617 | `6bdff5fd75b17a4c13a5f6c40fb8c6df4cc048c95b89d0254ccd337c5b0576c8` | `76f60b30` |
| `v0.1.88-platform-release-identity.v4.json` | `394166552` | 1609 | `0d227c2f716038e46c29e6dce1234ff1968406fcb6fa6b34816de5369434da73` | `76f60b30` |
| `v0.1.89-platform-release-identity.v4.json` | `394168254` | 1602 | `4f2c87a4b0ee0f4095451be19453b4bec2b8046da2406249ffab923c01d4b723` | `76f60b30` |
| `v0.1.90-platform-release-identity.v4.json` | `394272505` | 1609 | `5c871591b776efb56c80f803b0122ef6a438c71430359425ff47ed715f2cdf48` | `62f6ec1a` |
| `v0.1.91-platform-release-identity.v4.json` | `394276899` | 1604 | `dbf4aae45fcb489f09d7302654a13fd93f97b16f671a3844153917fb922c6f4b` | `62f6ec1a` |
| `v0.1.92-platform-release-identity.v4.json` | `394278457` | 1617 | `0379fc667e68621cf11515c405ebaac2db7c501a0ae80356d3f7d07208f89d5a` | `62f6ec1a` |
| `v0.1.93-platform-release-identity.v4.json` | `394279891` | 1610 | `faacd90559806609f25efbfc6771127bd22034809663df888e4a90c03e2caaf0` | `62f6ec1a` |
| `v0.1.94-platform-release-identity.v4.json` | `394322192` | 1633 | `20528ec98a5f3d2fc3bce6f3db0002d416cdb7e3fab2cda0fb011c3e1c6bb8af` | `62f6ec1a` (its own source) |

The asset IDs are `582841108`, `582860293`, `582866767`, `582918818` and
`583061105` in the same order; each was downloaded GET-only and its SHA-256
compared against the `digest` the REST release record reports.

They carry only already-public facts: the repository name and object ID,
source and executor commit SHAs, workflow run IDs, the fragment path and its
SHA-256, and the schema URL. No credential, host, path or account identifier
appears in any of them.

They exist because a hand-written sample would not have caught the defect they
pin. The executor `10ee0a67` that signed `v0.1.81` later became the source of
`v0.1.91`, the executor `76f60b30` that signed the eight edges `v0.1.82`…
`v0.1.89` in one drain became the source of `v0.1.93`, and `62f6ec1a` drained
`v0.1.90`…`v0.1.93` before publishing itself as `v0.1.94` — each time the
retired window's membership refusal turned against edges that were already
published and can never be reissued (issues #391 and #393). Issue #395
replaced that refusal with the executor RELATION, and these real bytes are what
prove the relation admits every one of them with no table and no pin:
`test_every_published_identity_validates_through_the_executor_relation` walks
all of them through the production validators at this head.

`v0.1.94` is the ordinary-path control in the same set: its executor IS its
source, so it must validate with no ancestry proof at all.

`derived-window-2026-09-23.json` beside them is the one-off side-by-side dump
taken at base commit `62f6ec1` while the frozen table still existed: for each of
the thirteen rows it holds what the table asserted and the same facts derived
from the repository's tags, git objects and the GitHub run listings, and every
pair is byte-equal. The offline suites read their ledger from it rather than
re-walking all 86 post-floor tags per module, and
`LedgerDerivationTests.test_the_shipped_derivation_reproduces_the_dump_from_git`
proves the shipped derivation still reproduces it.
