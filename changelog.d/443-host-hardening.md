### Security

- Add the host hardening tree: a redacted host manifest and assessor runner, a protected-package remover for the unused desktop, proxy, wallet and telemetry surfaces, a per-service egress allowlist, kernel lockdown and sysctl baselines, unit sandboxing, journal sealing, security-only unattended upgrades with `needrestart`, a daily integrity timer and a minimal audit rule set, each with a live verifier and a timed revert; ADR 0018 records the design, the replacement evaluation and the open segment-isolation decisions.
