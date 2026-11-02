### Security

- Host hardening follow-ups from the live run and review of #444: the time daemon's sandbox tolerates a missing statistics directory and can write its PID file, root-owned NTP sockets pass the egress allowlist, the sshd listener drop-in sorts after every other, IPv6 is disabled with a reapply instead of a reconnect, the units component arms its revert before staging and never reverts twice, a failed restore is reported, the egress verifier checks time sync and no longer probes the mirror as root, and the lane-ruling row names the toggle-guard allowlist entry.
