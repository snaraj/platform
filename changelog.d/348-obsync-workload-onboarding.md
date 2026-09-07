- Give the obsync workload the platform-side authority it needs and nothing
  more: the `obsidian` namespace under restricted Pod Security, a hash-bound
  ResourceQuota and LimitRange derived from its own capacity evidence document
  rather than the sites' shared one, the reconciler ServiceAccount, the
  impersonation and release-reconciler Roles, and a helm-reconciler Role whose
  claim-lifecycle rule confers no authority over any backing volume, class,
  node or provisioner.
- Add the workload's own Tunnel connector to the `cloudflare-public` chart —
  its own instance, token Secret name, token revision and origin-egress leg —
  and point that leg at the in-cluster TLS proxy rather than at the
  application. The obsync server speaks plain HTTP, so a connector-matching
  rule on the application would hand the connector its cleartext listener; the
  admitted edges are connector to proxy on the TLS port and proxy to
  application on the HTTP port, with no connector-to-application allowance in
  any contributing policy. The proxy identity is a declared placeholder that
  no Pod carries until the security lane's reviewed deployment supplies the
  real one, so the leg fails closed rather than reading closed while admitting
  the connector, and a negative fixture proves the connector identity cannot be
  substituted back in.
- Make the reviewed capacity contract per namespace instead of one shared map,
  in `scripts/validate_repository.py` and both Conftest suites: each namespace
  binds an exact five-value quota to the exact bytes of its own evidence
  document, and a namespace with no entry has no admissible budget at all. A
  namespace carrying another namespace's approved budget or evidence hash is a
  new refusal, proven by a negative test in each direction.
- Record the reviewable proposal for everything this repository must not write
  itself in `docs/design/obsync-onboarding.md`: the private WARP-routed
  Tunnel with no public hostname and no public DNS record, in-cluster TLS
  termination and the `edge.mode: none` consequence that follows from it, the
  operator storage ceremony, and the doubled receipt closure that refuses a
  third identity tuple until snaraj/obsync publishes v0.1.0.
