### Security

- The Cloudflare account audit now expects DNSSEC to be active on lidersea.com, as on the other two zones. The owner enabled it on 2026-11-02 (#154). Until Cloudflare's registrar publishes the zone's DS record, the zone reads `pending`, and the audit reports that as a finding.
