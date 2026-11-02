# Onboarding a Windows PC as an administrative client

The host accepts SSH only from the local tunnel connector, and the connector
accepts only connections that arrive over the private route from a device
enrolled in the owner's Zero Trust organization. A new client is therefore an
enrollment plus the same Access policy. Nothing changes on the host, the
firewall, or the gateway.

## Steps

1. **Install the WARP client** from Cloudflare's download page and sign in
   with the Zero Trust organization name. Choose the Gateway with WARP mode.
2. **Enroll.** The enrollment policy decides who may join; the device shows
   as connected in the client. The private route is pushed to the device.
3. **Satisfy device posture.** The SSH Access policy requires the login
   method and every device-posture check the organization defines (the laptop
   satisfies the same set). A failing check is shown in the client's posture
   view; fix it there, do not relax the policy.
4. **Create a hardware-backed SSH key** (`ssh-keygen -t ed25519-sk`) and have
   the owner add its public half to the administrator account on the host.
   Software keys work but the laptop's standard is a passphrase-protected key
   without agent caching; match or exceed it.
5. **Client configuration**: an `ssh_config` entry for the host whose
   `HostName` is the private-route address recorded in the laptop-only operator
   guide, `IdentitiesOnly yes`, `ForwardAgent no`, `PasswordAuthentication no`.
6. **Prove it**: with WARP connected, `ssh <host> true` succeeds; with WARP
   disconnected, the same command fails to connect. Record both outcomes.

## What this does not do

It does not open a LAN path, add a firewall rule, or change the route. If the
PC should also administer the cluster, it uses `kubectl` over the same SSH
session; the API server is never exposed to the admin plane (PLAT-DEC-001).
