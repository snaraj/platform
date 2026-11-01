### Security

- Select the supported Flux 2.10.0 controller set and cloudflared 2026.10.7, whose authenticated ARM64 binaries use Go 1.27.3, and containerd 2.3.7 for its core runtime advisory fixes (#418, #420, #421). Preserve narrowed controller roles, connector boundaries and the host installer's trusted-launcher stop. Record remaining dependency conditions separately; these source pins neither suppress findings nor prove a live rollout.
