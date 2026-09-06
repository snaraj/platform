# Tunnel token rotation

Host-token installation is retired from this repository. Credential changes
require a separately reviewed owner procedure using trusted staged code and
private inputs. The retained runtime redaction canary remains blocked pending
its trusted launcher; it must not be used as evidence that a rotation succeeded.
Never bypass that boundary with mutable checkout code, ad-hoc `sudo` or manual
copying. The standalone token validator checks canonical Base64 and the exact
account/Tunnel binding without printing fields.

Host tokens use restricted systemd credential custody but are not encrypted at
rest. Device theft or root compromise requires force-disconnect and rotation.
Preserve independent physical/LAN recovery and prove the new service invocation
uses the new credential before considering a rotation complete.

`pi-admin` and each public site hold separate Tunnel tokens. Never rotate more
than one in a single change. A remotely managed Tunnel token is a bearer
credential: anyone holding it can run a connector for that Tunnel.

Cloudflare rotation has two important semantics:

- after rotation, the old token cannot establish a new connection;
- connectors that were already connected with the old token remain connected
  until they restart or Cloudflare force-disconnects the Tunnel connections.

Therefore an old token is never a post-rotation rollback credential. Routine
rotation preserves service with existing connections while the new token is
installed. Compromise response rotates first, force-disconnects every existing
connection, and accepts downtime while trusted connectors receive the new
token. Physical or trusted-LAN recovery is the admin-path fallback.

Never place either Tunnel token or the API bearer used for rotation in a command
line, shell history, Git, chat, logs, an unprotected operational artifact.
Use a protected file or process-local environment, disable shell tracing, and
clear it immediately afterward.

## Public connectors — routine rotation, one site per ceremony

Each site is one identity tuple, and no member's name is ever derived from
another's suffix: Cloudflare Tunnel `naranjo-online`, Deployment
`naranjo-online-tunnel`, Secret `naranjo-online-tunnel-token`; and Cloudflare
Tunnel `lidersea-com`, Deployment `lidersea-com-tunnel`, Secret
`lidersea-com-tunnel-token`. `<site>` is one of those two Tunnel names and that
connector's `values.yaml` key; the other is the PEER. `pi-websites` is denied.

1. Keep `pi-admin` and physical/LAN recovery working and record the peer
   Secret's `resourceVersion` and `creationTimestamp`. In a reviewed window,
   have the owner rotate the Cloudflare Tunnel named `<site>` and capture its
   new token into a protected mode-0600 file without printing it; replicas may
   stay connected, but the old token cannot reconnect them.
2. Create the `cloudflare-public/<site>-tunnel-token` Secret on the cluster
   from that file. The token never enters the repository in any encoding, the
   release Kustomization stays at its exact two resources, and the only
   committed half is `connectors.<site>.tokenRevision`.
3. Render, policy-check, and secret-scan the exact diff. After merge, watch the
   `<site>-tunnel` Deployment's surge-free rollout (`maxSurge: 0`, one replica,
   so it drains and replaces) and run public, terminal-404, origin-denial tests.
4. Prove the peer untouched: its Secret's `resourceVersion` and
   `creationTimestamp` still equal step 1's, its Deployment still healthy.
5. Confirm the Cloudflare Tunnel `<site>` shows no old-token connector, then
   delete the protected old-token file. Never restore it: preserve admin
   recovery, stop that site's rollout, and rotate again for a different token.

Compromise of one `<site>` token: do step 1, then force-disconnect that one
Tunnel's connections with the dashboard control or a short-lived API token
holding exactly the connector-write permission —
`DELETE /accounts/<ACCOUNT_ID>/cfd_tunnel/<TUNNEL_ID>/connections`, whose
`<TUNNEL_ID>` is the UUID of the Cloudflare Tunnel named `<site>` and never
anything resolved from the `<site>-tunnel` Deployment. Never put either bearer
in the URL or command line. That site takes downtime because every old-token
connector, a malicious one included, otherwise stays active; the peer keeps
serving. Then do steps 2 to 5, revoke the API token against non-secret
revocation evidence, and never restore the compromised token.

## Admin connector — routine rotation

1. Preserve physical/LAN recovery and at least two working sessions. Have the
   owner rotate only `pi-admin` and capture the new token in a protected file
   without printing it.
2. No repository host-token installation path exists. Specify and independently
   review a new owner transaction that atomically replaces and verifies the
   credential; otherwise do not replace it or restart `pi-admin`.
3. Through that reviewed transaction, atomically replace only the
   root-owned systemd credential, restart `pi-admin`, require the exact-main
   active-credential equality/redaction canary, and run WARP-on, WARP-off,
   unauthorized identity/device, and control-plane-stopped tests. Public
   connector health must remain unchanged.
4. Delete the protected old-token file after the new connector is healthy. If
   the new credential fails, stop the unit and recover over physical/LAN access;
   correct the new credential or perform another forward rotation. The old token
   cannot reconnect after rotation and is not a rollback path.

## Admin connector — suspected or confirmed compromise

1. Retain physical/LAN recovery, rotate only `pi-admin`, and immediately
   force-disconnect all of its existing connections using the same protected
   dashboard/API procedure. Accept loss of remote administration during repair.
2. No repository host-token installation path exists. Stop the unit and use
   physical/LAN recovery until a new credential-replacement and verification
   transaction has been independently reviewed; do not bypass this boundary.
3. Through that reviewed transaction, atomically install the new root-owned
   credential, restart `pi-admin`, and run every WARP and
   control-plane-stopped test before relying on it.
4. Revoke the short-lived API token, remove protected copies of the compromised
   Tunnel token, and prove both public connectors are unchanged. Never restore
   a compromised token.

Revalidate the current behavior immediately before live rotation:

- <https://developers.cloudflare.com/tunnel/advanced/tunnel-tokens/>
