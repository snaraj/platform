### Fixed

- `verify-exposure.sh` accepts the edge's own answer to an unconfigured hostname, HTTP 530 with `error code: 1016`, as a denial only while that name has no A or AAAA answer in public DNS (a signed zone answers NOERROR with no data, an unsigned one NXDOMAIN). A 4xx still passes; any other status, a 530 with another code such as 1033, a failed lookup or tenant content is refused. The live gate stopped at this step before, so its port probes never ran.
