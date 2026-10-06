#!/usr/bin/env python3
"""Render launcher for the frozen Live Office backend (LO-2026-10-06-R1).

Why this exists: backend/office_api.py is a FROZEN release artifact
(sha256 978658c8de0ca9077e53203301ccef86d4b3f49acc7e9e99093f11f1430701b5)
and binds 127.0.0.1 only. Render's router + health checker must reach the
service on all interfaces, so this launcher (deployment config, NOT part of
the frozen artifact) starts the frozen backend on loopback and forwards
0.0.0.0:$PORT -> 127.0.0.1:<inner> byte-for-byte. API behavior, hashes, and
QA results are unchanged.

Usage: python backend/launcher.py   (reads $PORT, defaults 10000)
"""
import os
import select
import socket
import subprocess
import sys
import threading

INNER_PORT = 18787
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


def main() -> int:
    port = int(os.environ.get("PORT", "10000"))
    backend = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "office_api.py"), str(INNER_PORT)],
        stdout=sys.stdout, stderr=sys.stderr,
    )
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(128)
    print(f"launcher: 0.0.0.0:{port} -> 127.0.0.1:{INNER_PORT}", flush=True)
    try:
        while True:
            client, _ = srv.accept()
            upstream = socket.create_connection(("127.0.0.1", INNER_PORT))
            threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        backend.terminate()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
