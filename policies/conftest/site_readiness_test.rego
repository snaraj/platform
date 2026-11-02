package main

import rego.v1

# The readiness rule's PENDING direction. Since issue #429 no website is
# pending, so no fixture can reach it; these tests override the pending set
# instead. The next site admitted pending relies on this arm: while its
# selection is the sentinel, a ready claim would be false.
readiness_test_release(ready) := {
  "apiVersion": "helm.toolkit.fluxcd.io/v2",
  "kind": "HelmRelease",
  "metadata": {"name": "hospedajedonlolo-com", "namespace": "hospedajedonlolo-com"},
  "spec": {"suspend": true, "values": {"deploymentReady": ready}},
}

readiness_test_pending := {"obsidian", "hospedajedonlolo-com"}

test_a_pending_site_claiming_readiness_is_refused if {
  deny["HelmRelease hospedajedonlolo-com values must contain exactly deploymentReady: false"] with input as readiness_test_release(true)
    with pending_chart_namespaces as readiness_test_pending
}

test_a_pending_site_stating_not_ready_is_admitted if {
  denials := deny with input as readiness_test_release(false)
    with pending_chart_namespaces as readiness_test_pending
  not any_readiness_denial(denials)
}

test_the_same_site_active_must_claim_readiness if {
  deny["HelmRelease hospedajedonlolo-com values must contain exactly deploymentReady: true"] with input as readiness_test_release(false)
}

any_readiness_denial(denials) if {
  some msg in denials
  startswith(msg, "HelmRelease hospedajedonlolo-com values must contain exactly deploymentReady")
}
