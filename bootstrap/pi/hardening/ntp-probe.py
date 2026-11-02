#!/usr/bin/env python3
"""One NTP client exchange, nothing else.

Usage: python3 -I -B ntp-probe.py <host> [timeout-seconds]
Exit 0 when the host answers a mode-3 client packet with a mode-4 server
packet within the timeout, 1 otherwise. The verifier runs this as each uid
that owns a time socket on the host, so a passing run proves that uid's path
through the egress allowlist with a fresh packet, not with history.
"""

from __future__ import annotations

import socket
import sys

NTP_PORT = 123
# LI 0, version 4, mode 3 (client); the remaining 47 bytes are zero.
CLIENT_PACKET = b"\x23" + b"\x00" * 47


def exchange(host: str, timeout: float) -> bool:
    try:
        addr = socket.getaddrinfo(host, NTP_PORT, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
    except socket.gaierror:
        return False
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(CLIENT_PACKET, addr)
            data, _ = sock.recvfrom(512)
        except OSError:
            return False
    return len(data) >= 48 and (data[0] & 0x07) == 4


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print("usage: ntp-probe.py <host> [timeout-seconds]", file=sys.stderr)
        return 2
    timeout = float(argv[2]) if len(argv) == 3 else 4.0
    return 0 if exchange(argv[1], timeout) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
