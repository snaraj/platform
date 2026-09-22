### Fixed

- Pin the recorded executor of an already published frozen edge as `executor_sha` and require the signed identity to equal it exactly, so `v0.1.81` still validates now that the run which published it is itself `v0.1.91`'s frozen source; every unpinned edge keeps the untouched refusal of a frozen source presenting itself as another edge's executor, and a pin no published Release records is refused when the module loads.
- Freeze the twelfth historical-recovery edge, `v0.1.92`, so the merge that repaired the backlog derivation stays publishable after main moves past it.
