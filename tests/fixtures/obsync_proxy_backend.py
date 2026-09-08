"""Synthetic, credential-free backend for the isolated TLS proxy smoke only."""

import hashlib
import http.server
import json
import threading

RELEASE = threading.Event()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path == "/stream":
            RELEASE.clear()
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.write(b"5\r\nstart\r\n")
            self.wfile.flush()
            if RELEASE.wait(10):
                self.wfile.write(b"4\r\nstop\r\n0\r\n\r\n")
                self.wfile.flush()
            return
        self.reply({"ready": True})

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 <= size <= 4 * 1024 * 1024:
            self.send_error(413)
            return
        body = self.rfile.read(size)
        if self.path == "/release":
            RELEASE.set()
        self.reply({
            "method": self.command,
            "target": self.path,
            "headers": {key.lower(): value for key, value in self.headers.items()},
            "body_sha256": hashlib.sha256(body).hexdigest(),
        })

    def reply(self, payload):
        encoded = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


if __name__ == "__main__":
    # No published port: this address exists only on the test's internal
    # Docker network. The fixture is never included in a production artifact.
    http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
