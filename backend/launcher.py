#!/usr/bin/env python3
"""Render launcher for the Live Office backend + ASTRA relay (LO-2026-10-06-R1).

Why this exists: backend/office_api.py is a FROZEN release artifact
(sha256 978658c8de0ca9077e53203301ccef86d4b3f49acc7e9e99093f11f1430701b5)
and binds 127.0.0.1 only. Render's router + health checker must reach the
service on all interfaces, so this launcher (deployment config, NOT part of
the frozen artifact) starts the frozen backend on loopback and forwards
0.0.0.0:$PORT -> 127.0.0.1:<inner>.

ASTRA relay (Ric Dev Summary 2026-10-11): backend/relay_astra.py runs as a
separate loopback process (127.0.0.1:18788). This launcher now routes by HTTP
path: /webhook/astra* -> relay, everything else -> frozen backend.
office_api.py itself is UNCHANGED; its endpoints are untouched.

Usage: python backend/launcher.py   (reads $PORT, defaults 10000)
"""
import os
import select
import socket
import subprocess
import sys
import threading
from urllib.parse import urlparse

INNER_PORT = 18787   # frozen office_api.py
RELAY_PORT = 18788   # relay_astra.py (ASTRA public webhook relay)
HERE = os.path.dirname(os.path.abspath(__file__))


def pipe(a: socket.socket, b: socket.socket) -> None:
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 300)
            if not r:
                break
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()


def route_path(head: bytes) -> str:
    """Return 'relay' if the HTTP request targets /webhook/astra*, else 'backend'."""
    try:
        line = head.split(b"\r\n", 1)[0].decode("latin-1")
        target = line.split()[1]
        path = urlparse(target).path
    except Exception:
        return "backend"
    if path == "/webhook/astra" or path.startswith("/webhook/astra/"):
        return "relay"
    return "backend"


def handle_client(client: socket.socket) -> None:
    try:
        client.settimeout(10)
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 16384:
            chunk = client.recv(4096)
            if not chunk:
                break
            buf += chunk
        dest = route_path(buf)
        upstream = socket.create_connection(
            ("127.0.0.1", RELAY_PORT if dest == "relay" else INNER_PORT),
            timeout=10,
        )
        upstream.settimeout(None)  # blocking, like the original forwarder
        if buf:
            upstream.sendall(buf)
        client.settimeout(None)
        pipe(client, upstream)
    except OSError:
        try:
            client.close()
        except OSError:
            pass


def main() -> int:
    port = int(os.environ.get("PORT", "10000"))
    backend = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "office_api.py"), str(INNER_PORT)],
        stdout=sys.stdout, stderr=sys.stderr,
    )
    relay = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "relay_astra.py")],
        stdout=sys.stdout, stderr=sys.stderr,
    )
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(128)
    print(f"launcher: 0.0.0.0:{port} -> backend 127.0.0.1:{INNER_PORT}, "
          f"relay 127.0.0.1:{RELAY_PORT} (/webhook/astra*)", flush=True)
    try:
        while True:
            client, _ = srv.accept()
            threading.Thread(target=handle_client, args=(client,),
                             daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        backend.terminate()
        relay.terminate()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
