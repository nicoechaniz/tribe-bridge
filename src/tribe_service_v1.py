#!/usr/bin/env python3
"""Bounded HTTP service exposing the Tribe v1 durable broker contract."""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import tribe_protocol_v1 as protocol
from tribe_broker_v1 import (
    BrokerError,
    MessageConflict,
    RequestReplay,
    SQLiteBroker,
)
from tribe_directory_v1 import Directory, DirectoryError, strict_json
from tribe_transport_v1 import validate_request


MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
BUILD_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{7,64}$")


class TribeV1Service:
    def __init__(
        self,
        broker: SQLiteBroker,
        directory: Directory,
        *,
        build_commit: str,
        clock_ms=None,
        directory_loader=None,
    ):
        if not BUILD_COMMIT_PATTERN.fullmatch(build_commit):
            raise ValueError("build_commit must be a lowercase git SHA")
        self.broker = broker
        self.directory = directory
        self.build_commit = build_commit
        self.clock_ms = clock_ms or (lambda: int(time.time() * 1000))
        self.directory_loader = directory_loader

    def _current_directory(self) -> Directory:
        if self.directory_loader is not None:
            self.directory = self.directory_loader(self.clock_ms())
        return self.directory

    def health(self) -> dict[str, Any]:
        directory = self._current_directory()
        broker_runtime = {
            key: value
            for key, value in self.broker.runtime_info().items()
            if key != "path"
        }
        return {
            "ok": True,
            "protocol": "tribe/v1",
            "build_commit": self.build_commit,
            "directory_epoch": directory.epoch,
            "directory_sha256": directory.hash,
            "broker": broker_runtime,
        }

    def post(self, path: str, wrapper: Any) -> tuple[int, dict[str, Any]]:
        now = self.clock_ms()
        directory = self._current_directory()
        auth, body = validate_request(
            wrapper,
            directory=directory,
            method="POST",
            path=path,
            now_ms=now,
        )
        self.broker.record_authenticated_request(
            auth["agent_id"],
            auth["request_id"],
            now_ms=now,
            expires_at_ms=auth["expires_at_ms"],
        )
        if path == "/v1/messages":
            if (
                not isinstance(body, dict)
                or body.get("sender", {}).get("id") != auth["agent_id"]
            ):
                raise protocol.ProtocolError("unauthorized_sender")
            context = directory.context(
                sender_id=auth["agent_id"], now_ms=now
            )
            receipt = self.broker.enqueue(
                body, context, received_at_ms=now
            )
            return (200 if receipt["duplicate"] else 201), receipt

        if path == "/v1/claims":
            if not isinstance(body, dict) or set(body) != {
                "recipient_id",
                "limit",
                "lease_ms",
            }:
                raise protocol.ProtocolError("malformed_request")
            if body["recipient_id"] != auth["agent_id"]:
                raise protocol.ProtocolError("unauthorized_receiver")
            if (
                not isinstance(body["limit"], int)
                or isinstance(body["limit"], bool)
                or not 1 <= body["limit"] <= 3
            ):
                raise protocol.ProtocolError("malformed_request")
            claims = self.broker.claim(
                body["recipient_id"],
                limit=body["limit"],
                lease_ms=body["lease_ms"],
                now_ms=now,
            )
            return 200, {"claims": claims}

        if path == "/v1/acks":
            if (
                not isinstance(body, dict)
                or body.get("receiver_id") != auth["agent_id"]
            ):
                raise protocol.ProtocolError("unauthorized_receiver")
            context = directory.context(
                receiver_id=auth["agent_id"], now_ms=now
            )
            result = self.broker.acknowledge(
                body, context, now_ms=now
            )
            return 200, result
        raise protocol.ProtocolError("unknown_endpoint")


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, *, max_workers: int):
        super().__init__(address, handler)
        self._slots = threading.BoundedSemaphore(max_workers)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: 23\r\n"
                    b"Connection: close\r\n\r\n"
                    b'{"error":"server_busy"}'
                )
            finally:
                request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class TribeV1Handler(BaseHTTPRequestHandler):
    server_version = "TribeBridgeV1"
    protocol_version = "HTTP/1.1"

    @property
    def service(self) -> TribeV1Service:
        return self.server.service

    def log_message(self, format, *args):
        if os.environ.get("TRIBE_V1_VERBOSE") == "1":
            sys.stderr.write(
                f"[tribe-v1] {self.client_address[0]} {args[0]}\n"
            )

    def _respond(self, status: int, value: dict[str, Any]) -> None:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        if len(encoded) > MAX_RESPONSE_BYTES:
            status = 500
            encoded = b'{"error":"response_too_large"}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        if self.path != "/v1/health":
            self._respond(404, {"error": "not_found"})
            return
        self._respond(200, self.service.health())

    def do_POST(self):
        length_header = self.headers.get("Content-Length")
        try:
            length = int(length_header or "")
        except ValueError:
            self._respond(400, {"error": "invalid_request"})
            return
        if (
            self.headers.get("Content-Type") != "application/json"
            or length <= 0
            or length > MAX_REQUEST_BYTES
        ):
            self._respond(
                413 if length > MAX_REQUEST_BYTES else 400,
                {"error": "invalid_request"},
            )
            return
        self.connection.settimeout(10)
        raw = self.rfile.read(length)
        if len(raw) != length:
            self._respond(400, {"error": "invalid_request"})
            return
        try:
            wrapper = strict_json(raw)
            status, result = self.service.post(self.path, wrapper)
            self._respond(status, result)
        except MessageConflict:
            self._respond(409, {"error": "message_id_conflict"})
        except RequestReplay:
            self._respond(409, {"error": "request_replay"})
        except (protocol.ProtocolError, DirectoryError, ValueError):
            self._respond(400, {"error": "invalid_request"})
        except BrokerError:
            self._respond(503, {"error": "broker_unavailable"})


def build_service_from_environment() -> tuple[TribeV1Service, str, int, int]:
    required = {
        "TRIBE_V1_DB": os.environ.get("TRIBE_V1_DB"),
        "TRIBE_V1_DIRECTORY": os.environ.get("TRIBE_V1_DIRECTORY"),
        "TRIBE_V1_GOVERNANCE_ROOTS": os.environ.get(
            "TRIBE_V1_GOVERNANCE_ROOTS"
        ),
        "TRIBE_V1_DIRECTORY_STATE": os.environ.get(
            "TRIBE_V1_DIRECTORY_STATE"
        ),
        "TRIBE_V1_BUILD_COMMIT": os.environ.get("TRIBE_V1_BUILD_COMMIT"),
    }
    missing = [key for key, value in required.items() if not value]
    if missing:
        raise RuntimeError(
            "missing required environment: " + ", ".join(missing)
        )
    now = int(time.time() * 1000)
    directory = Directory.load(
        required["TRIBE_V1_DIRECTORY"],
        required["TRIBE_V1_GOVERNANCE_ROOTS"],
        required["TRIBE_V1_DIRECTORY_STATE"],
        now_ms=now,
    )
    broker = SQLiteBroker(
        required["TRIBE_V1_DB"],
        journal_mode=os.environ.get("TRIBE_V1_JOURNAL_MODE", "auto"),
    )
    bind = os.environ.get("TRIBE_V1_BIND", "127.0.0.1")
    if bind in {"0.0.0.0", "::"} and os.environ.get(
        "TRIBE_V1_ALLOW_GLOBAL_BIND"
    ) != "1":
        raise RuntimeError(
            "global bind requires TRIBE_V1_ALLOW_GLOBAL_BIND=1"
        )
    port = int(os.environ.get("TRIBE_V1_PORT", "8685"))
    workers = int(os.environ.get("TRIBE_V1_MAX_WORKERS", "16"))
    if not 1 <= workers <= 128:
        raise RuntimeError("TRIBE_V1_MAX_WORKERS must be 1..128")
    return (
        TribeV1Service(
            broker,
            directory,
            build_commit=required["TRIBE_V1_BUILD_COMMIT"],
            directory_loader=lambda current_ms: Directory.load(
                required["TRIBE_V1_DIRECTORY"],
                required["TRIBE_V1_GOVERNANCE_ROOTS"],
                required["TRIBE_V1_DIRECTORY_STATE"],
                now_ms=current_ms,
            ),
        ),
        bind,
        port,
        workers,
    )


def main() -> None:
    service, bind, port, workers = build_service_from_environment()
    server = BoundedThreadingHTTPServer(
        (bind, port), TribeV1Handler, max_workers=workers
    )
    server.service = service
    os.umask(0o077)
    server.serve_forever()


if __name__ == "__main__":
    main()
