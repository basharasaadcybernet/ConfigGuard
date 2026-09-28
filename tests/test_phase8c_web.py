"""Focused local-web security, UX contract, and packaging regressions for Phase 8C."""

from __future__ import annotations

import ast
import http.client
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http import HTTPStatus
from pathlib import Path
from typing import cast

import pytest

import configguard.cli as cli_module
from configguard.application import AssessmentService
from configguard.cli import ExitCode, main
from configguard.parsing import ConfigurationIngestor, ConfigurationInputError, InputErrorCode
from configguard.web import (
    LOOPBACK_HOST,
    LocalWebServer,
    WebApplication,
    WebServerStartError,
    create_web_server,
    run_web_server,
)

ROOT = Path(__file__).parents[1]
FIXTURES = Path(__file__).parent / "fixtures"
TOKEN = "synthetic-phase8c-request-token"
SECRET = "SYNTHETIC-PHASE8C-PRIVATE-MARKER"


@contextmanager
def _running_server(application: WebApplication | None = None) -> Iterator[LocalWebServer]:
    server = create_web_server(0, application or WebApplication(request_token=TOKEN))
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _request(
    server: LocalWebServer,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    port = cast(tuple[str, int], server.server_address)[1]
    connection = http.client.HTTPConnection(LOOPBACK_HOST, port, timeout=3)
    request_headers = dict(headers or {})
    request_headers.setdefault("Host", f"{LOOPBACK_HOST}:{port}")
    connection.request(method, path, body=body, headers=request_headers)
    response = connection.getresponse()
    payload = response.read()
    response_headers = {name.lower(): value for name, value in response.getheaders()}
    status = response.status
    connection.close()
    return status, response_headers, payload


def _upload_headers(filename: str = "synthetic-router.txt") -> dict[str, str]:
    return {
        "Content-Type": "application/octet-stream",
        "X-ConfigGuard-Filename": filename,
        "X-ConfigGuard-Token": TOKEN,
    }


def test_path_and_in_memory_assessments_use_the_same_service_pipeline() -> None:
    path = FIXTURES / "synthetic_ios_router.txt"
    service = AssessmentService()

    from_path = service.assess_path(path)
    from_bytes = service.assess_bytes(path.name, path.read_bytes())

    assert from_path == from_bytes
    assert len(from_path.findings) == 17
    assert from_path.to_public_dict()["report_schema_version"] == "1.0.0"


def test_in_memory_ingestion_reuses_size_encoding_binary_and_label_safety() -> None:
    ingestor = ConfigurationIngestor(max_bytes=32)
    source = ingestor.read_bytes(
        "C:/private/folder/synthetic.cfg", b"version 15.7\nhostname TEST\n"
    )

    assert source.label == "synthetic.cfg"
    assert "private" not in repr(source)
    for payload, expected in (
        (b"x" * 33, InputErrorCode.FILE_TOO_LARGE),
        (b"version 15.7\xff", InputErrorCode.UNSUPPORTED_ENCODING),
        (b"version 15.7\x00", InputErrorCode.BINARY_INPUT),
        (b" \n\t", InputErrorCode.EMPTY_INPUT),
    ):
        with pytest.raises(ConfigurationInputError) as caught:
            ingestor.read_bytes("private.cfg", payload)
        assert caught.value.code is expected


def test_web_help_and_port_validation_are_discoverable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["web", "--help"])
    help_output = capsys.readouterr().out

    assert caught.value.code == ExitCode.COMPLETED
    assert "127.0.0.1" in help_output
    assert "--port" in help_output
    assert "--no-open" in help_output
    assert "not uploaded to a cloud service" in help_output
    assert "configguard web --port 9000" in help_output
    assert "--host" not in help_output

    for value in ("0", "1023", "65536", "not-a-port"):
        with pytest.raises(SystemExit) as invalid:
            main(["web", "--port", value, "--no-open"])
        assert invalid.value.code == ExitCode.INVALID_INPUT
        capsys.readouterr()


def test_web_cli_passes_port_and_no_open_without_starting_other_commands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, bool]] = []

    def fake_server(*, port: int, open_browser: bool) -> None:
        calls.append((port, open_browser))

    monkeypatch.setattr(cli_module, "run_web_server", fake_server)

    assert main(["web", "--port", "9000", "--no-open"]) == ExitCode.COMPLETED
    assert calls == [(9000, False)]


def test_browser_opening_occurs_after_bind_and_failure_does_not_stop_server(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    events: list[str] = []

    class FakeServer:
        server_address = (LOOPBACK_HOST, 8765)

        def serve_forever(self, poll_interval: float) -> None:
            assert poll_interval == 0.25
            events.append("serve")
            raise KeyboardInterrupt

        def server_close(self) -> None:
            events.append("close")

    def create_after_bind(port: int) -> FakeServer:
        assert port == 8765
        events.append("bound")
        return FakeServer()

    def fail_to_open(url: str, *, new: int) -> bool:
        assert url == "http://127.0.0.1:8765"
        assert new == 2
        events.append("open")
        return False

    monkeypatch.setattr("configguard.web.create_web_server", create_after_bind)
    run_web_server(port=8765, browser_opener=fail_to_open)
    output = capsys.readouterr().out

    assert events == ["bound", "open", "serve", "close"]
    assert "Running at http://127.0.0.1:8765" in output
    assert "could not be opened automatically" in output
    assert "Stopping ConfigGuard" in output


def test_no_open_fully_disables_browser_opener(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []

    class FakeServer:
        server_address = (LOOPBACK_HOST, 8765)

        def serve_forever(self, poll_interval: float) -> None:
            del poll_interval
            events.append("serve")
            raise KeyboardInterrupt

        def server_close(self) -> None:
            events.append("close")

    def forbidden_opener(url: str, *, new: int) -> bool:
        del url, new
        raise AssertionError("browser opener must not be called")

    monkeypatch.setattr("configguard.web.create_web_server", lambda port: FakeServer())
    run_web_server(port=8765, open_browser=False, browser_opener=forbidden_opener)

    assert events == ["serve", "close"]


def test_server_binds_loopback_and_serves_health_index_and_assets() -> None:
    with _running_server() as server:
        assert cast(tuple[str, int], server.server_address)[0] == LOOPBACK_HOST
        health_status, health_headers, health_body = _request(server, "GET", "/api/health")
        index_status, index_headers, index_body = _request(server, "GET", "/")
        css_status, css_headers, css_body = _request(server, "GET", "/assets/app.css")
        js_status, js_headers, js_body = _request(server, "GET", "/assets/app.js")
        logo_status, logo_headers, logo_body = _request(server, "GET", "/assets/brand-mark.svg")

    assert health_status == index_status == css_status == js_status == logo_status == 200
    assert json.loads(health_body) == {"status": "ok", "version": "0.1.0"}
    assert health_headers["content-type"] == "application/json; charset=utf-8"
    assert index_headers["content-type"] == "text/html; charset=utf-8"
    assert css_headers["content-type"] == "text/css; charset=utf-8"
    assert js_headers["content-type"] == "text/javascript; charset=utf-8"
    assert logo_headers["content-type"] == "image/svg+xml"
    assert b"__CONFIGGUARD_REQUEST_TOKEN__" not in index_body
    assert TOKEN.encode() in index_body
    assert b"Static Network Configuration Security Auditor" in index_body
    assert b".drop-zone" in css_body
    assert b"/api/scan" in js_body
    assert logo_body.startswith(b"<?xml")
    for headers in (health_headers, index_headers, css_headers, js_headers, logo_headers):
        assert "access-control-allow-origin" not in headers
        assert headers["cache-control"] == "no-store"
        assert headers["connection"] == "close"
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-frame-options"] == "DENY"


def test_host_allowlist_and_cross_origin_preflight_are_rejected() -> None:
    with _running_server() as server:
        port = cast(tuple[str, int], server.server_address)[1]
        invalid_status, invalid_headers, invalid_body = _request(
            server,
            "GET",
            "/api/health",
            headers={"Host": "attacker.example"},
        )
        localhost_status, _, _ = _request(
            server,
            "GET",
            "/api/health",
            headers={"Host": f"localhost:{port}"},
        )
        options_status, options_headers, _ = _request(server, "OPTIONS", "/api/scan")

    assert invalid_status == HTTPStatus.BAD_REQUEST
    assert json.loads(invalid_body)["error"]["code"] == "invalid_host"
    assert localhost_status == HTTPStatus.OK
    assert options_status == HTTPStatus.METHOD_NOT_ALLOWED
    assert options_headers["allow"] == "GET, POST"
    assert "access-control-allow-origin" not in invalid_headers
    assert "access-control-allow-origin" not in options_headers


def test_valid_upload_matches_shared_engine_and_returns_existing_exports() -> None:
    payload = (FIXTURES / "synthetic_ios_router.txt").read_bytes()
    expected = AssessmentService().assess_bytes("synthetic-router.txt", payload).to_public_dict()

    with _running_server() as server:
        status, headers, body = _request(
            server,
            "POST",
            "/api/scan",
            body=payload,
            headers=_upload_headers(),
        )

    response = json.loads(body)
    assert status == HTTPStatus.OK
    assert headers["content-type"] == "application/json; charset=utf-8"
    assert response["assessment"] == expected
    assert len(response["assessment"]["findings"]) == 17
    assert json.loads(response["exports"]["json"])["report_schema_version"] == "1.0.0"
    assert response["exports"]["html"].startswith("<!doctype html>")
    assert response["exports"]["json_filename"] == "configguard-synthetic-router-assessment.json"
    assert response["exports"]["html_filename"] == "configguard-synthetic-router-report.html"
    assert "additional_evidence" in response["presentation"]


def test_secret_markers_and_uploaded_paths_never_reach_public_api() -> None:
    private_path = "C:/private/customer/Sensitive Router.cfg"
    source = (
        "version 15.7\n"
        "hostname SYNTHETIC-WEB\n"
        f"username TEST secret 9 {SECRET}\n"
        f"snmp-server community {SECRET} RW\n"
        "line vty 0 4\n"
        " transport input telnet\n"
        "end\n"
    ).encode()

    with _running_server() as server:
        status, _, body = _request(
            server,
            "POST",
            "/api/scan",
            body=source,
            headers=_upload_headers(private_path),
        )

    public = body.decode("utf-8")
    response = json.loads(body)
    assert status == HTTPStatus.OK
    assert SECRET not in public
    assert private_path not in public
    assert "C:/private" not in public
    assert "[REDACTED]" in public
    assert response["exports"]["json_filename"] == "configguard-sensitive-router-assessment.json"


@pytest.mark.parametrize(
    ("payload", "expected_status", "expected_code"),
    [
        (b"version 15.7\x00hostname TEST", HTTPStatus.BAD_REQUEST, "binary_input"),
        (b"version 15.7\xff", HTTPStatus.BAD_REQUEST, "unsupported_encoding"),
        (b" \n\t", HTTPStatus.BAD_REQUEST, "empty_input"),
        (
            b"system {\n host-name SYNTHETIC;\n}\n",
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "unsupported_configuration",
        ),
    ],
)
def test_invalid_uploads_return_safe_bounded_errors(
    payload: bytes,
    expected_status: HTTPStatus,
    expected_code: str,
) -> None:
    with _running_server() as server:
        status, _, body = _request(
            server,
            "POST",
            "/api/scan",
            body=payload,
            headers=_upload_headers("private-secret-name.cfg"),
        )

    response = json.loads(body)
    assert status == expected_status
    assert response["error"]["code"] == expected_code
    assert payload.decode("utf-8", errors="ignore") not in body.decode("utf-8")
    assert "private-secret-name" not in body.decode("utf-8")


def test_server_rejects_oversized_upload_before_reading_body() -> None:
    application = WebApplication(request_token=TOKEN)
    oversized = application.service.max_input_bytes + 1
    with _running_server(application) as server:
        status, _, body = _request(
            server,
            "POST",
            "/api/scan",
            body=b"",
            headers={**_upload_headers(), "Content-Length": str(oversized)},
        )

    assert status == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    assert json.loads(body)["error"]["code"] == "file_too_large"


def test_scan_requires_same_origin_request_token() -> None:
    source = b"version 15.7\nhostname SYNTHETIC\nend\n"
    headers = _upload_headers()
    headers.pop("X-ConfigGuard-Token")
    with _running_server() as server:
        status, _, body = _request(server, "POST", "/api/scan", body=source, headers=headers)

    assert status == HTTPStatus.FORBIDDEN
    assert json.loads(body)["error"]["code"] == "invalid_request_token"


def test_unexpected_analysis_failure_never_leaks_exception_or_private_path() -> None:
    class ExplodingService:
        max_input_bytes = 2 * 1024 * 1024

        def assess_bytes(self, label: str, data: bytes) -> None:
            del label, data
            raise RuntimeError(f"{SECRET} C:/private/customer/router.cfg")

    application = WebApplication(
        service=cast(AssessmentService, ExplodingService()),
        request_token=TOKEN,
    )
    with _running_server(application) as server:
        status, _, body = _request(
            server,
            "POST",
            "/api/scan",
            body=b"version 15.7\nhostname SYNTHETIC\nend\n",
            headers=_upload_headers(),
        )

    public = body.decode("utf-8")
    assert status == HTTPStatus.INTERNAL_SERVER_ERROR
    assert json.loads(body)["error"] == {
        "code": "analysis_failure",
        "message": "ConfigGuard could not complete the assessment safely.",
    }
    assert SECRET not in public
    assert "C:/private" not in public


def test_occupied_port_fails_cleanly_without_fallback_binding(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    first = create_web_server(0, WebApplication(request_token=TOKEN))
    occupied_port = cast(tuple[str, int], first.server_address)[1]
    try:
        with pytest.raises(WebServerStartError, match=str(occupied_port)):
            create_web_server(occupied_port, WebApplication(request_token=TOKEN))
    finally:
        first.server_close()

    def fail_server(*, port: int, open_browser: bool) -> None:
        del open_browser
        raise WebServerStartError(f"Port {port} is unavailable on the local loopback interface.")

    monkeypatch.setattr(cli_module, "run_web_server", fail_server)
    assert main(["web", "--port", str(occupied_port), "--no-open"]) == ExitCode.INVALID_INPUT
    output = capsys.readouterr()
    assert output.out == ""
    assert "web_start_failure" in output.err
    assert "Traceback" not in output.err
    assert "0.0.0.0" not in output.err


def test_web_implementation_has_no_persistence_or_external_frontend_resources() -> None:
    web_source = (ROOT / "src/configguard/web.py").read_text(encoding="utf-8")
    tree = ast.parse(web_source)
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imported.isdisjoint({"tempfile", "sqlite3", "subprocess", "requests", "httpx"})

    javascript = (ROOT / "src/configguard/web_assets/app.js").read_text(encoding="utf-8")
    index = (ROOT / "src/configguard/web_assets/index.html").read_text(encoding="utf-8")
    combined = f"{javascript}\n{index}".lower()
    for forbidden in (
        "localstorage",
        "sessionstorage",
        "indexeddb",
        "innerhtml",
        "navigator.sendbeacon",
        'fetch("http',
        'src="http',
        'href="http',
    ):
        assert forbidden not in combined
    assert 'fetch("/api/scan"' in combined


def test_bundled_application_assets_load_without_repository_relative_paths() -> None:
    application = WebApplication(request_token=TOKEN)

    assert TOKEN.encode() in application.index()
    assert application.asset("/assets/app.css") is not None
    assert application.asset("/assets/app.js") is not None
    assert application.asset("/assets/brand-mark.svg") is not None
    assert application.asset("/assets/../web.py") is None


def test_frontend_exposes_required_upload_results_filters_exports_and_reset_controls() -> None:
    index = (ROOT / "src/configguard/web_assets/index.html").read_text(encoding="utf-8")
    javascript = (ROOT / "src/configguard/web_assets/app.js").read_text(encoding="utf-8")
    stylesheet = (ROOT / "src/configguard/web_assets/app.css").read_text(encoding="utf-8")

    for control_id in (
        "drop-zone",
        "file-input",
        "scan-button",
        "download-json",
        "download-html",
        "new-scan",
        "overview-grid",
        "diagnostics-section",
        "limitations-list",
    ):
        assert f'id="{control_id}"' in index
    for filter_name in ("all", "findings", "secure", "unknown", "not_applicable"):
        assert f'data-filter="{filter_name}"' in index
    for interaction in (
        'addEventListener("drop"',
        'addEventListener("change"',
        'fetch("/api/scan"',
        "renderResults",
        "URL.createObjectURL",
        "resetApplication",
    ):
        assert interaction in javascript
    assert "@media (max-width: 980px)" in stylesheet
    assert "@media (max-width: 680px)" in stylesheet
    assert "@media (prefers-reduced-motion: reduce)" in stylesheet


def test_personal_brand_identity_and_palette_are_bundled() -> None:
    index = (ROOT / "src/configguard/web_assets/index.html").read_text(encoding="utf-8")
    stylesheet = (ROOT / "src/configguard/web_assets/app.css").read_text(encoding="utf-8")
    logo = (ROOT / "src/configguard/web_assets/brand-mark.svg").read_text(encoding="utf-8")

    assert '<link rel="icon" type="image/svg+xml" href="/assets/brand-mark.svg">' in index
    assert 'src="/assets/brand-mark.svg" alt="Bashar Asaad logo"' in index
    assert "Bashar Asaad" in index
    assert "بشار أسعد" in index
    assert "Cybersecurity" in index and "Networking" in index
    for color in ("#020a23", "#2f63e0", "#536171", "#1fba83", "#22d6e7", "#e5e5e5"):
        assert color in stylesheet.lower()
    assert "<svg" in logo
