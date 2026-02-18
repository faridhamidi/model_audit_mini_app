#!/usr/bin/env python3
"""Standalone local mini app for Codex model routing audit."""

from __future__ import annotations

import argparse
import csv
import json
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


CSV_HEADERS = [
    "timestamp_utc",
    "timestamp_epoch_ms",
    "model",
    "cwd",
    "sandbox_mode",
    "approval_policy",
    "session_file",
]

HTML_NAME = "model_audit_dashboard.html"
CSV_NAME = "model_audit_data.csv"


@dataclass
class TurnRow:
    timestamp: datetime
    model: str
    cwd: str
    sandbox_mode: str
    approval_policy: str
    session_file: str


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    raw = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def as_utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_sandbox_mode(policy: Any) -> str:
    if isinstance(policy, dict):
        return str(policy.get("type") or policy.get("mode") or "unknown")
    return "unknown"


def extract_turn_rows(sessions_dir: Path) -> list[TurnRow]:
    rows: list[TurnRow] = []
    if not sessions_dir.exists():
        return rows

    for file_path in sorted(sessions_dir.rglob("*.jsonl")):
        try:
            with file_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if entry.get("type") != "turn_context":
                        continue

                    payload = entry.get("payload") or {}
                    model = payload.get("model")
                    if not model:
                        continue
                    ts = parse_timestamp(entry.get("timestamp"))
                    if ts is None:
                        continue

                    rows.append(
                        TurnRow(
                            timestamp=ts,
                            model=str(model),
                            cwd=str(payload.get("cwd") or "unknown"),
                            sandbox_mode=normalize_sandbox_mode(payload.get("sandbox_policy")),
                            approval_policy=str(payload.get("approval_policy") or "unknown"),
                            session_file=str(file_path),
                        )
                    )
        except OSError:
            continue

    rows.sort(key=lambda item: item.timestamp)
    return rows


def write_csv_atomic(csv_path: Path, rows: list[TurnRow]) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="",
        delete=False,
        dir=str(csv_path.parent),
        prefix=".tmp_model_audit_",
        suffix=".csv",
    ) as temp_file:
        writer = csv.DictWriter(temp_file, fieldnames=CSV_HEADERS)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "timestamp_utc": as_utc_iso(row.timestamp),
                    "timestamp_epoch_ms": int(row.timestamp.timestamp() * 1000),
                    "model": row.model,
                    "cwd": row.cwd,
                    "sandbox_mode": row.sandbox_mode,
                    "approval_policy": row.approval_policy,
                    "session_file": row.session_file,
                }
            )
        temp_path = Path(temp_file.name)

    temp_path.replace(csv_path)


class AuditAppContext:
    def __init__(self, sessions_dir: Path, reports_dir: Path) -> None:
        self.sessions_dir = sessions_dir
        self.reports_dir = reports_dir
        self.html_path = reports_dir / HTML_NAME
        self.csv_path = reports_dir / CSV_NAME
        self.last_refresh_meta: dict[str, Any] | None = None

    def refresh_csv(self) -> dict[str, Any]:
        generated_at = datetime.now(timezone.utc)
        rows = extract_turn_rows(self.sessions_dir)
        write_csv_atomic(self.csv_path, rows)

        message: str | None = None
        if not self.sessions_dir.exists():
            message = f"Sessions directory does not exist: {self.sessions_dir}"
        elif not rows:
            message = "No turn_context records with model found in sessions logs."

        meta = {
            "status": "ok",
            "rows_written": len(rows),
            "generated_at_utc": as_utc_iso(generated_at),
            "source_sessions_dir": str(self.sessions_dir),
            "csv_path": str(self.csv_path),
        }
        if message:
            meta["message"] = message
        self.last_refresh_meta = meta
        return meta

    def load_dashboard_html(self) -> str:
        text = self.html_path.read_text(encoding="utf-8")
        refresh_time = ""
        if self.last_refresh_meta:
            refresh_time = str(self.last_refresh_meta.get("generated_at_utc", ""))
        text = text.replace("__SOURCE_SESSIONS_DIR__", str(self.sessions_dir))
        text = text.replace("__CSV_RELATIVE_PATH__", "/data.csv")
        text = text.replace("__LAST_REFRESH_UTC__", refresh_time)
        return text


class AuditDashboardHandler(BaseHTTPRequestHandler):
    server_version = "ModelAuditLocalApp/1.0"

    @property
    def app(self) -> AuditAppContext:
        return self.server.app_context  # type: ignore[attr-defined]

    def _send_bytes(
        self,
        code: int,
        body: bytes,
        content_type: str,
        *,
        cache_control: str = "no-store",
    ) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache_control)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self._send_bytes(code, body, "application/json; charset=utf-8")

    def _send_not_found(self) -> None:
        self._send_json(
            HTTPStatus.NOT_FOUND,
            {"status": "error", "message": "Not found"},
        )

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        sys.stdout.write(
            "%s - - [%s] %s\n"
            % (
                self.address_string(),
                self.log_date_time_string(),
                format % args,
            )
        )

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/":
            try:
                html = self.app.load_dashboard_html().encode("utf-8")
            except FileNotFoundError:
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {
                        "status": "error",
                        "message": f"Dashboard template missing: {self.app.html_path}",
                    },
                )
                return
            self._send_bytes(HTTPStatus.OK, html, "text/html; charset=utf-8")
            return

        if parsed.path == "/data.csv":
            if not self.app.csv_path.exists():
                meta = self.app.refresh_csv()
                if meta.get("status") != "ok":
                    self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, meta)
                    return
            body = self.app.csv_path.read_bytes()
            self._send_bytes(HTTPStatus.OK, body, "text/csv; charset=utf-8")
            return

        self._send_not_found()

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/refresh":
            try:
                meta = self.app.refresh_csv()
            except Exception as exc:  # noqa: BLE001
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"status": "error", "message": f"Refresh failed: {exc}"},
                )
                return
            self._send_json(HTTPStatus.OK, meta)
            return

        self._send_not_found()


def parse_args() -> argparse.Namespace:
    default_reports_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Run local model audit mini app (CSV-backed dashboard).",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Bind port (default: 8765)")
    parser.add_argument(
        "--sessions-dir",
        default=str(Path.home() / ".codex" / "sessions"),
        help="Codex sessions directory (default: ~/.codex/sessions)",
    )
    parser.add_argument(
        "--reports-dir",
        default=str(default_reports_dir),
        help=f"Reports directory containing {HTML_NAME} and {CSV_NAME}",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    sessions_dir = Path(args.sessions_dir).expanduser().resolve()
    reports_dir = Path(args.reports_dir).expanduser().resolve()

    app_context = AuditAppContext(sessions_dir=sessions_dir, reports_dir=reports_dir)
    if not app_context.html_path.exists():
        raise SystemExit(f"Missing dashboard template: {app_context.html_path}")

    startup_meta = app_context.refresh_csv()
    print(
        f"[model-audit] startup refresh: rows={startup_meta['rows_written']} generated_at={startup_meta['generated_at_utc']}"
    )
    print(f"[model-audit] source sessions: {sessions_dir}")
    print(f"[model-audit] csv path: {app_context.csv_path}")

    server = ThreadingHTTPServer((args.host, args.port), AuditDashboardHandler)
    server.app_context = app_context  # type: ignore[attr-defined]

    print(f"[model-audit] serving at http://{args.host}:{args.port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
