### Changed

- Move `hospedajedonlolo-com` out of the pending chart set at its first release: the policy now requires the selected `0.1.1` digest, an unsuspended release and `deploymentReady: true` for it, and refuses the sentinel. The allow and deny fixtures follow the active composition byte for byte, and new Rego unit tests keep the readiness rule's pending direction covered now that no website is pending.
