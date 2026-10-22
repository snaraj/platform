## Security

- Isolate the three Flux controllers from the distrusted public CA using a
  reviewed, read-only public trust bundle. Preserve anonymous Git/OCI, existing
  authorization and network controls, and the create-only installer boundary.
  This interim containment still requires patched vendor controller builds;
  source publication does not activate it on an existing installation.
