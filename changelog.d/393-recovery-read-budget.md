### Fixed

- Derive the recovery reader's per-run read budget from the frozen window instead of a fixed cap, because a selection re-proves every published edge and the fixed cap stopped being reachable at the tenth, making that edge unpublishable; the cap stays a hard bound, its measured per-edge and fixed costs are stated where they are derived, and the seconds bound is now checked against the same window at import.
- Freeze the thirteenth historical-recovery edge, `v0.1.93`, so the merge that derives those bounds stays publishable after main moves past it.
