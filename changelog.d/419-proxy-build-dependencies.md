### Security

- Select NGINX 1.30.6 Alpine slim from the upstream-maintained `nginx/nginx-unprivileged` repository. The immutable artifact removes unused vulnerable Brotli/curl packages and updates musl and zlib to their vendor-fixed versions. Preserve the proxy configuration and pod security boundaries; source publication does not perform or prove a rollout.
