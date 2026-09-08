"""Exercise the real proxy config using isolated, ephemeral local Docker inputs.

No personal vault, external endpoint, cluster access or credential is used.
There are no published sockets; a client runs inside the internal test network. Every object
has an unpredictable per-attempt label; cleanup refuses foreign same-name state.
Docker registry credentials are not loaded. DOCKER_HOST may select the caller's
already-authorized local engine; no new context or authentication is installed.
"""

import hashlib
import http.client
import json
from pathlib import Path
import re
import signal
import ssl
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
IMAGE_KEY = "OBSYNC_TLS_PROXY_IMAGE"
BACKEND_KEY = "OBSYNC_TLS_TEST_BACKEND_IMAGE"
STRIPPED = (
    "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
    "X-Forwarded-Port", "X-Forwarded-Server", "X-Real-IP", "True-Client-IP",
    "CF-Connecting-IP", "CF-Connecting-IPv6", "CF-Pseudo-IPv4", "CF-IPCountry",
    "CF-Ray", "CF-Visitor", "CF-Worker", "CF-Access-Jwt-Assertion",
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def execute(argv, *, timeout=60, check=True):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if check:
        require(result.returncode == 0, f"{Path(argv[0]).name} operation failed")
    return result


def pin(key):
    matches = re.findall(r"(?m)^" + key + r"=(\S+)$", (ROOT / "versions.env").read_text())
    require(len(matches) == 1 and re.fullmatch(r"docker\.io/[a-z0-9./:-]+@sha256:[0-9a-f]{64}", matches[0]), "invalid test image pin")
    return matches[0]


def connection(port, context):
    return http.client.HTTPSConnection("sync.example.invalid", port, timeout=4, context=context)


def request(port, context, method, target, body=None, headers=None):
    conn = connection(port, context)
    try:
        conn.request(method, target, body=body, headers=headers or {})
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def check_transport():
    port = 8443
    context = ssl.create_default_context(cafile="/test-trust/tls.crt")
    for _ in range(40):
        try:
            if request(port, context, "GET", "/readyz")[0] == 200:
                break
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.25)
    else:
        raise RuntimeError("proxy did not become ready")
    for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        context.minimum_version = context.maximum_version = version
        require(request(port, context, "GET", "/readyz")[0] == 200, "TLS version failed")
    try:
        request(port, ssl.create_default_context(), "GET", "/readyz")
    except ssl.SSLCertVerificationError:
        pass
    else:
        raise RuntimeError("untrusted leaf was accepted")
    auth = {key: "fixture-only" for key in ("Authorization", "Cookie", "X-Obsync-Device", "X-Obsync-Ts", "X-Obsync-Nonce", "X-Obsync-Sig")}
    headers = {**auth, **{key: "untrusted-fixture" for key in STRIPPED}, "Host": "sync.example.invalid"}
    body = b"synthetic-obsync-boundary\n" * 100000
    target = "/transport-fixture?value=a%2Fb"
    status, payload = request(port, context, "POST", target, body, headers)
    received = json.loads(payload)
    require(status == 200 and received["method"] == "POST" and received["target"] == target, "request target changed")
    require(received["body_sha256"] == hashlib.sha256(body).hexdigest(), "upload changed")
    require(all(received["headers"].get(key.lower()) == value for key, value in auth.items()), "auth header changed")
    require(not any(key.lower() in received["headers"] for key in STRIPPED), "attribution header forwarded")
    require(received["headers"]["host"] == "sync.example.invalid", "Host changed")
    stream = connection(port, context)
    try:
        stream.request("GET", "/stream")
        response = stream.getresponse()
        require(response.status == 200 and response.read(5) == b"start", "first stream chunk buffered")
        require(request(port, context, "POST", "/release", b"")[0] == 200, "stream release failed")
        require(response.read() == b"stop", "stream tail changed")
    finally:
        stream.close()
    print("OBSYNC_PROXY_TRANSPORT=PASS")


def smoke():
    attempt = uuid.uuid4().hex
    label = "obsync-proxy-smoke-attempt"
    names = {kind: f"obsync-proxy-smoke-{attempt}-{kind}" for kind in ("network", "backend", "proxy")}
    with tempfile.TemporaryDirectory(prefix="obsync-proxy-smoke-") as temporary:
        scratch = Path(temporary)
        docker = ["docker", "--config", str(scratch / "docker")]
        (scratch / "docker").mkdir(mode=0o700)
        certs = scratch / "certs"
        certs.mkdir(mode=0o755)
        execute([
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-days", "1", "-subj", "/CN=sync.example.invalid",
            "-addext", "subjectAltName=DNS:sync.example.invalid",
            "-addext", "basicConstraints=critical,CA:FALSE",
            "-keyout", str(certs / "tls.key"), "-out", str(certs / "tls.crt"),
        ])
        # This disposable self-signed leaf authenticates only this test. The
        # outer 0700 directory protects it on the host; the read-only bind must
        # be readable by the container's unrelated uid. No trust store changes.
        for path in certs.iterdir():
            path.chmod(0o444)
        image, backend_image = pin(IMAGE_KEY), pin(BACKEND_KEY)
        for image_ref in (image, backend_image):
            execute(docker + ["pull", image_ref], timeout=180)
        attempted = []
        try:
            attempted.append(("network", names["network"]))
            execute(docker + ["network", "create", "--internal", "--label", f"{label}={attempt}", names["network"]])
            common = ["--detach", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                      "--network", names["network"], "--label", f"{label}={attempt}"]
            attempted.append(("container", names["backend"]))
            execute(docker + ["run", *common, "--name", names["backend"], "--user", "65532:65532",
                "--network-alias", "obsync.obsidian.svc.cluster.local", "--memory", "64m", "--cpus", "0.5",
                "--mount", f"type=bind,source={ROOT / 'tests/fixtures/obsync_proxy_backend.py'},target=/fixture.py,readonly",
                "--mount", f"type=bind,source={ROOT / 'tests/obsync_proxy_smoke.py'},target=/fixtures/tests/obsync_proxy_smoke.py,readonly",
                "--mount", f"type=bind,source={certs / 'tls.crt'},target=/test-trust/tls.crt,readonly",
                "--entrypoint", "python", backend_image, "-B", "/fixture.py"])
            attempted.append(("container", names["proxy"]))
            execute(docker + ["run", *common, "--name", names["proxy"], "--user", "101:101", "--memory", "256m", "--cpus", "0.5",
                "--network-alias", "sync.example.invalid",
                "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16777216,uid=101,gid=101,mode=0700",
                "--mount", f"type=bind,source={ROOT / 'kubernetes/platform/obsync-tls-proxy/nginx.conf'},target=/etc/obsync-proxy/nginx.conf,readonly",
                "--mount", f"type=bind,source={certs},target=/etc/obsync-tls,readonly",
                "--entrypoint", "nginx", image, "-c", "/etc/obsync-proxy/nginx.conf", "-g", "daemon off;", "-e", "/dev/null"])
            info = json.loads(execute(docker + ["container", "inspect", names["proxy"]]).stdout)[0]
            published = {key: value for key, value in info["NetworkSettings"]["Ports"].items() if value}
            require(not published and not info["HostConfig"]["PortBindings"], "unexpected published socket")
            result = execute(docker + ["exec", names["backend"], "python", "-B", "/fixtures/tests/obsync_proxy_smoke.py", "--client"], check=False)
            require(result.returncode == 0 and result.stdout.strip() == "OBSYNC_PROXY_TRANSPORT=PASS",
                    "transport fixture failed: " + result.stderr[-2000:])
            logs = execute(docker + ["logs", names["proxy"]])
            require("fixture-only" not in logs.stdout + logs.stderr, "credential marker appeared in logs")
        finally:
            # Finish bounded cleanup even if a second interrupt arrives. A
            # failed removal does not prevent cleanup of other owned objects.
            handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
            errors = []
            for kind, name in reversed(attempted):
                try:
                    result = execute(docker + [kind, "inspect", name], check=False)
                    if result.returncode:
                        require(result.stdout.strip() == "[]" and result.stderr.strip() in {
                            f"Error response from daemon: No such {kind}: {name}",
                            f"Error: No such {kind}: {name}",
                            f"Error response from daemon: network {name} not found",
                        }, "cleanup discovery unknown")
                        continue
                    obj = json.loads(result.stdout)[0]
                    labels = obj["Config"]["Labels"] if kind == "container" else obj["Labels"]
                    require(labels.get(label) == attempt, "refusing foreign test object")
                    identity = obj["Id"]
                    require(re.fullmatch(r"[0-9a-f]{64}", identity), "invalid cleanup identity")
                    command = ["container", "rm", "--force", identity] if kind == "container" else ["network", "rm", identity]
                    execute(docker + command)
                    residue = execute(docker + [kind, "ls", "--filter", f"id={identity}", "--format", "{{.ID}}"] + (["--all"] if kind == "container" else [])).stdout.strip()
                    require(not residue, "test object residue")
                except Exception as error:
                    errors.append(str(error))
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
            require(not errors, "cleanup incomplete: " + "; ".join(errors))
    print("OBSYNC_PROXY_LOCAL_TLS_HEADERS_UPLOAD_STREAM=PASS cleanup=PASS")


if __name__ == "__main__":
    def interrupted(_signum, _frame):
        raise InterruptedError("proxy smoke interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    if sys.argv[1:] == ["--client"]:
        check_transport()
    else:
        require(len(sys.argv) == 1, "unexpected arguments")
        smoke()
