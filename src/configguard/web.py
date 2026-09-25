"""Loopback-only HTTP application for the bundled ConfigGuard web interface."""

from __future__ import annotations

import json
import secrets
import webbrowser
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from typing import cast
from urllib.parse import unquote, urlsplit

from configguard import __version__
from configguard.application import AssessmentService
from configguard.parsing import (
    ConfigurationInputError,
    ConfigurationParseError,
    InputErrorCode,
    UnsupportedPlatformError,
)
from configguard.reporting import additional_evidence_guidance, render_html, render_json

LOOPBACK_HOST = "127.0.0.1"
DEFAULT_WEB_PORT = 8765
_ALLOWED_UPLOAD_TYPES = {"application/octet-stream", "text/plain"}
_ASSET_TYPES = {
    "/assets/app.css": "text/css; charset=utf-8",
    "/assets/app.js": "text/javascript; charset=utf-8",
}


class WebServerStartError(RuntimeError):
    """A safe local-server startup failure suitable for CLI output."""


class WebApplication:
    """Stateless HTTP-facing adapter around the shared assessment service."""

    def __init__(
        self,
        service: AssessmentService | None = None,
        request_token: str | None = None,
    ) -> None:
        self.service = service or AssessmentService()
        self.request_token = request_token or secrets.token_urlsafe(32)
        asset_root = files("configguard").joinpath("web_assets")
        index_template = asset_root.joinpath("index.html").read_text(encoding="utf-8")
        self._index = index_template.replace(
            "__CONFIGGUARD_REQUEST_TOKEN__",
            self.request_token,
        ).encode("utf-8")
        self._assets = {
            path: asset_root.joinpath(path.rsplit("/", maxsplit=1)[-1]).read_bytes()
            for path in _ASSET_TYPES
        }

    def index(self) -> bytes:
        """Return the in-memory index with its per-process request token."""

        return self._index

    def asset(self, path: str) -> tuple[str, bytes] | None:
        """Return one explicitly bundled asset without arbitrary path traversal."""

        content = self._assets.get(path)
        if content is None:
            return None
        return _ASSET_TYPES[path], content

    def scan(self, filename: str, payload: bytes) -> dict[str, object]:
        """Assess an ephemeral upload and return sanitized data plus existing exports."""

        report = self.service.assess_bytes(filename, payload)
        stem = _safe_export_stem(filename)
        return {
            "assessment": report.to_public_dict(),
            "presentation": {
                "additional_evidence": {
                    finding.rule_id: guidance
                    for finding in report.findings
                    if (guidance := additional_evidence_guidance(finding)) is not None
                }
            },
            "exports": {
                "json": render_json(report),
                "html": render_html(report),
                "json_filename": f"configguard-{stem}-assessment.json",
                "html_filename": f"configguard-{stem}-report.html",
            },
        }


class LocalWebServer(ThreadingHTTPServer):
    """IPv4 loopback server carrying one in-memory application instance."""

    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, port: int, application: WebApplication) -> None:
        self.application = application
        super().__init__((LOOPBACK_HOST, port), ConfigGuardRequestHandler)


class ConfigGuardRequestHandler(BaseHTTPRequestHandler):
    """Serve a minimal same-origin UI/API without request-content logging."""

    protocol_version = "HTTP/1.1"
    server_version = "ConfigGuard"
    sys_version = ""

    @property
    def application(self) -> WebApplication:
        return cast(LocalWebServer, self.server).application

    def version_string(self) -> str:
        return "ConfigGuard"

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def do_GET(self) -> None:
        if not self._host_is_allowed():
            self._send_error(HTTPStatus.BAD_REQUEST, "invalid_host", "The Host header is invalid.")
            return
        path = urlsplit(self.path).path
        if path == "/":
            self._send_bytes(HTTPStatus.OK, self.application.index(), "text/html; charset=utf-8")
            return
        if path == "/api/health":
            self._send_json(HTTPStatus.OK, {"status": "ok", "version": __version__})
            return
        asset = self.application.asset(path)
        if asset is not None:
            content_type, content = asset
            self._send_bytes(HTTPStatus.OK, content, content_type)
            return
        self._send_error(HTTPStatus.NOT_FOUND, "not_found", "The requested resource was not found.")

    def do_POST(self) -> None:
        if not self._host_is_allowed():
            self._send_error(HTTPStatus.BAD_REQUEST, "invalid_host", "The Host header is invalid.")
            return
        if urlsplit(self.path).path != "/api/scan":
            self._send_error(
                HTTPStatus.NOT_FOUND, "not_found", "The requested resource was not found."
            )
            return
        supplied_token = self.headers.get("X-ConfigGuard-Token", "")
        if not secrets.compare_digest(supplied_token, self.application.request_token):
            self._send_error(
                HTTPStatus.FORBIDDEN,
                "invalid_request_token",
                "The local request token is missing or invalid.",
            )
            return
        if self.headers.get("Transfer-Encoding") is not None:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "unsupported_transfer_encoding",
                "Chunked uploads are not accepted.",
            )
            return
        content_type = self.headers.get_content_type().lower()
        if content_type not in _ALLOWED_UPLOAD_TYPES:
            self._send_error(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                "Upload the configuration as plain text or an octet-stream.",
            )
            return
        length_header = self.headers.get("Content-Length")
        if length_header is None:
            self._send_error(
                HTTPStatus.LENGTH_REQUIRED,
                "length_required",
                "A bounded Content-Length header is required.",
            )
            return
        try:
            content_length = int(length_header)
        except ValueError:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_content_length",
                "The upload length is invalid.",
            )
            return
        if content_length < 0:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_content_length",
                "The upload length is invalid.",
            )
            return
        if content_length > self.application.service.max_input_bytes:
            self.close_connection = True
            self._send_error(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                InputErrorCode.FILE_TOO_LARGE.value,
                "The selected configuration exceeds the configured size limit.",
            )
            return

        payload = self.rfile.read(content_length)
        filename = unquote(self.headers.get("X-ConfigGuard-Filename", "configuration.txt"))
        try:
            response = self.application.scan(filename, payload)
        except ConfigurationInputError as error:
            status = (
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE
                if error.code is InputErrorCode.FILE_TOO_LARGE
                else HTTPStatus.BAD_REQUEST
            )
            self._send_error(status, error.code.value, str(error))
            return
        except UnsupportedPlatformError:
            self._send_error(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "unsupported_configuration",
                "The configuration is unsupported or could not be identified safely.",
            )
            return
        except ConfigurationParseError:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_configuration",
                "The selected configuration could not be parsed.",
            )
            return
        except Exception:
            self._send_error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "analysis_failure",
                "ConfigGuard could not complete the assessment safely.",
            )
            return
        self._send_json(HTTPStatus.OK, response)

    def do_OPTIONS(self) -> None:
        if not self._host_is_allowed():
            self._send_error(HTTPStatus.BAD_REQUEST, "invalid_host", "The Host header is invalid.")
            return
        self._send_error(
            HTTPStatus.METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "Cross-origin preflight requests are not accepted.",
            extra_headers={"Allow": "GET, POST"},
        )

    def _host_is_allowed(self) -> bool:
        host = self.headers.get("Host", "").lower()
        port = cast(tuple[str, int], self.server.server_address)[1]
        return host in {
            f"{LOOPBACK_HOST}:{port}",
            f"localhost:{port}",
        }

    def _send_json(self, status: HTTPStatus, payload: dict[str, object]) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send_bytes(status, body, "application/json; charset=utf-8")

    def _send_error(
        self,
        status: HTTPStatus,
        code: str,
        message: str,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self._send_json_with_headers(
            status,
            {"error": {"code": code, "message": message}},
            extra_headers,
        )

    def _send_json_with_headers(
        self,
        status: HTTPStatus,
        payload: dict[str, object],
        extra_headers: dict[str, str] | None,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send_bytes(
            status,
            body,
            "application/json; charset=utf-8",
            extra_headers=extra_headers,
        )

    def _send_bytes(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.close_connection = True
        self.send_response(status.value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", _content_security_policy(content_type))
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True


def create_web_server(
    port: int = DEFAULT_WEB_PORT,
    application: WebApplication | None = None,
) -> LocalWebServer:
    """Bind an IPv4 loopback server or raise a safe startup error."""

    try:
        return LocalWebServer(port, application or WebApplication())
    except OSError:
        raise WebServerStartError(
            f"Port {port} is unavailable on the local loopback interface."
        ) from None


def run_web_server(
    *,
    port: int = DEFAULT_WEB_PORT,
    open_browser: bool = True,
    browser_opener: Callable[..., bool] | None = None,
) -> None:
    """Run the local web service until interrupted, with no child process."""

    server = create_web_server(port)
    actual_port = cast(tuple[str, int], server.server_address)[1]
    url = f"http://{LOOPBACK_HOST}:{actual_port}"
    print("ConfigGuard Local Web UI")
    print(f"Running at {url}")
    print("Configuration files are processed locally and are not uploaded to a cloud service.")
    print("Press Ctrl+C to stop.", flush=True)
    if open_browser:
        opener = browser_opener or webbrowser.open
        try:
            opened = opener(url, new=2)
        except Exception:
            opened = False
        if not opened:
            print("The browser could not be opened automatically; open the URL above manually.")
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nStopping ConfigGuard Local Web UI.")
    finally:
        server.server_close()


def _safe_export_stem(filename: str) -> str:
    basename = filename.replace("\\", "/").rsplit("/", maxsplit=1)[-1]
    stem = basename.rsplit(".", maxsplit=1)[0]
    safe = "".join(character.lower() if character.isalnum() else "-" for character in stem)
    collapsed = "-".join(part for part in safe.split("-") if part)
    return (collapsed or "configuration")[:64]


def _content_security_policy(content_type: str) -> str:
    if content_type.startswith("text/html"):
        return (
            "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; "
            "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        )
    return "default-src 'none'; frame-ancestors 'none'"
