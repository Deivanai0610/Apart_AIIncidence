from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .gateway import GatewayApplication
from .handlers import Application, RequestError


class ChimeraRequestHandler(BaseHTTPRequestHandler):
    application: Application | GatewayApplication

    def do_GET(self) -> None:
        self._respond_to("GET")

    def do_POST(self) -> None:
        self._respond_to("POST")

    def _respond_to(self, method: str) -> None:
        try:
            if method == "GET":
                status, payload = self.application.get(self.path)
            else:
                status, payload = self.application.post(self.path, self)
        except RequestError as error:
            status, payload = error.status, {"error": error.message}
        except Exception:
            status, payload = HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "service failure"}
        self._send_json(status, payload)

    def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    role = os.environ.get("SERVICE_ROLE", "")
    port = int(os.environ.get("PORT", "8080"))
    if role == "gateway":
        ChimeraRequestHandler.application = GatewayApplication()
    else:
        ChimeraRequestHandler.application = Application(role)
    server = ThreadingHTTPServer(("0.0.0.0", port), ChimeraRequestHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
