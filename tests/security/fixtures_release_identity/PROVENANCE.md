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

They carry only already-public facts: the repository name and object ID,
source and executor commit SHAs, workflow run IDs, the fragment path and its
SHA-256, and the schema URL. No credential, host, path or account identifier
appears in any of them.

They exist because a hand-written sample would not have caught the defect they
pin (issue #391). The executor `10ee0a67` that signed `v0.1.81` later became
the frozen source of `v0.1.91`, and the executor `76f60b30` that signed the
eight edges `v0.1.82`…`v0.1.89` in one drain became the frozen source of
`v0.1.93` (issue #393) — each time the window's membership refusal turned
against edges that were already published and can never be reissued. Only the
real bytes prove the repair admits these exact published identities, and that
the unpinned rule refuses them.

The set is a contiguous prefix of the frozen window, `v0.1.81` first: every
frozen edge that has been published has its asset here, and a later drain adds
the edges it publishes in the same pull request that freezes its executor.
