#!/usr/bin/env python3
"""A tiny command queue between a test host and a Windows (virtual) machine.

Standard library only. The host runs this server; inside Windows the
PowerShell runner (runner.ps1, served by this server at /r) asks it for the
next command every second, runs it, and posts the result back. Nothing in
Windows has to be installed or configured, and no password is needed: one
line typed once into a PowerShell window starts the runner:

    iex(iwr http://<host>:8765/r -UseB).Content

Bind it ONLY to the address the virtual machine reaches the host on (for a
VMware Fusion NAT network, the vmnet8 host address, for example
192.168.248.1), never to 0.0.0.0: whoever can reach this port can run
commands in that Windows session.

Layout of the session folder (--dir):
    files/      files the guest may download:   GET /f/<name>
    queue/      one JSON command per file, oldest first: {"id", "ps"}
    results/    the runner's answers (<id>.json) and uploads (PUT /u/<name>)
"""

import argparse
import http.server
import json
import os
import socketserver
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def make_handler(root: str, host: str, port: int):
    files = os.path.join(root, "files")
    queue = os.path.join(root, "queue")
    results = os.path.join(root, "results")
    for d in (files, queue, results):
        os.makedirs(d, exist_ok=True)

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):            # keep a log in the session folder
            with open(os.path.join(root, "server.log"), "a", encoding="utf-8") as fh:
                fh.write(time.strftime("%H:%M:%S ") + (fmt % args) + "\n")

        def _send(self, code, body=b"", ctype="application/octet-stream"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_GET(self):                               # noqa: N802
            if self.path == "/r":
                with open(os.path.join(HERE, "runner.ps1"), encoding="utf-8") as fh:
                    text = fh.read().replace("__BASE__", f"http://{host}:{port}")
                return self._send(200, text.encode("utf-8"), "text/plain; charset=utf-8")
            if self.path.startswith("/f/"):
                name = os.path.basename(self.path[3:])
                path = os.path.join(files, name)
                if not os.path.isfile(path):
                    return self._send(404)
                with open(path, "rb") as fh:
                    return self._send(200, fh.read())
            if self.path == "/next":
                with open(os.path.join(root, "heartbeat"), "w") as fh:
                    fh.write(str(time.time()))
                pending = sorted(n for n in os.listdir(queue) if n.endswith(".json"))
                if not pending:
                    return self._send(204)
                path = os.path.join(queue, pending[0])
                with open(path, "rb") as fh:
                    body = fh.read()
                os.remove(path)
                return self._send(200, body, "application/json")
            return self._send(404)

        def do_PUT(self):                               # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length)
            if self.path.startswith("/u/"):
                name = os.path.basename(self.path[3:])
            elif self.path.startswith("/result/"):
                name = os.path.basename(self.path[8:]) + ".json"
            else:
                return self._send(404)
            tmp = os.path.join(results, name + ".part")
            with open(tmp, "wb") as fh:
                fh.write(body)
            os.replace(tmp, os.path.join(results, name))
            return self._send(200)

    return Handler


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--bind", required=True, help="host address the VM reaches")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--dir", required=True, help="session folder")
    a = ap.parse_args()
    if a.bind in ("0.0.0.0", "", "::"):
        print("Refusing to listen on every interface; give the VM network's host address.")
        return 2
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer((a.bind, a.port),
                                         make_handler(os.path.abspath(a.dir), a.bind, a.port)) as srv:
        print(f"serving {a.dir} on http://{a.bind}:{a.port}", flush=True)
        srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
