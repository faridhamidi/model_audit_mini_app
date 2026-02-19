#!/usr/bin/env python3
"""Standalone local mini app for Codex model routing and usage audit."""

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
    "event_type",
    "thread_id",
    "thread_label",
    "conversation_id",
    "query_id",
    "query_index",
    "model",
    "cwd",
    "sandbox_mode",
    "approval_policy",
    "session_file",
    "message_role",
    "message_text",
    "query_text",
    "tool_name",
    "tool_call_id",
    "tool_start_epoch_ms",
    "tool_end_epoch_ms",
    "tool_duration_ms",
    "input_tokens",
    "output_tokens",
    "cached_input_tokens",
    "reasoning_output_tokens",
    "total_tokens",
]

HTML_NAME = "model_audit_dashboard.html"
CSV_NAME = "model_audit_data.csv"
CODEX_GLOBAL_STATE_PATH = Path.home() / ".codex" / ".codex-global-state.json"


@dataclass
class AuditEventRow:
    timestamp: datetime
    event_type: str
    thread_id: str
    thread_label: str | None = None
    conversation_id: str | None = None
    query_id: str | None = None
    query_index: int | None = None
    model: str = "unknown"
    cwd: str = "unknown"
    sandbox_mode: str = "unknown"
    approval_policy: str = "unknown"
    session_file: str = ""
    message_role: str | None = None
    message_text: str | None = None
    query_text: str | None = None
    tool_name: str | None = None
    tool_call_id: str | None = None
    tool_start_epoch_ms: int | None = None
    tool_end_epoch_ms: int | None = None
    tool_duration_ms: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cached_input_tokens: int | None = None
    reasoning_output_tokens: int | None = None
    total_tokens: int | None = None


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


def coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            if "." in text:
                return int(float(text))
            return int(text)
        except ValueError:
            return None
    return None


def extract_response_message_text(payload: dict[str, Any]) -> str:
    content = payload.get("content")
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if not isinstance(item, dict):
                continue
            text = item.get("text")
            if isinstance(text, str) and text.strip():
                parts.append(text)
        return "\n".join(parts).strip()
    text = payload.get("text")
    if isinstance(text, str):
        return text.strip()
    return ""


def parse_tool_duration_ms(output_payload: Any) -> int | None:
    parsed: Any = output_payload
    if isinstance(output_payload, str):
        text = output_payload.strip()
        if text:
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = None

    if not isinstance(parsed, dict):
        return None

    metadata = parsed.get("metadata")
    if isinstance(metadata, dict):
        dur_ms = coerce_int(metadata.get("duration_ms"))
        if dur_ms is not None:
            return max(0, dur_ms)
        dur_seconds = metadata.get("duration_seconds")
        if isinstance(dur_seconds, (int, float)):
            return max(0, int(dur_seconds * 1000))

    dur_ms = coerce_int(parsed.get("duration_ms"))
    if dur_ms is not None:
        return max(0, dur_ms)
    dur_seconds = parsed.get("duration_seconds")
    if isinstance(dur_seconds, (int, float)):
        return max(0, int(dur_seconds * 1000))
    return None


def load_thread_title_map(global_state_path: Path = CODEX_GLOBAL_STATE_PATH) -> dict[str, str]:
    try:
        raw = global_state_path.read_text(encoding="utf-8")
    except OSError:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(payload, dict):
        return {}
    section = payload.get("thread-titles")
    if not isinstance(section, dict):
        return {}
    titles = section.get("titles")
    if not isinstance(titles, dict):
        return {}
    mapped: dict[str, str] = {}
    for key, value in titles.items():
        if not isinstance(key, str):
            continue
        if not isinstance(value, str):
            continue
        title = value.strip()
        if title:
            mapped[key.strip()] = title
    return mapped


def make_thread_label(first_query_text: str, thread_id: str, cwd: str) -> str:
    lines = [line.strip() for line in first_query_text.splitlines() if line.strip()]
    for line in lines:
        low = line.lower()
        if low.startswith("<environment_context>"):
            continue
        if low.startswith("# context from my ide setup"):
            continue
        if low.startswith("## my request for codex"):
            continue
        cleaned = line.lstrip("-*# ").strip()
        if cleaned:
            return cleaned[:72]

    base = Path(cwd).name if cwd and cwd != "unknown" else "thread"
    suffix = thread_id.split("-")[0][:8] if thread_id else "unknown"
    return f"{base}-{suffix}"[:72]


def extract_event_rows(sessions_dir: Path) -> list[AuditEventRow]:
    rows: list[AuditEventRow] = []
    if not sessions_dir.exists():
        return rows

    thread_title_map = load_thread_title_map()

    for file_path in sorted(sessions_dir.rglob("*.jsonl")):
        file_rows: list[AuditEventRow] = []
        thread_id = file_path.stem
        context_model = "unknown"
        context_cwd = "unknown"
        context_sandbox_mode = "unknown"
        context_approval_policy = "unknown"
        first_query_text = ""
        first_known_cwd = "unknown"

        query_index = 0
        current_query_id = "unknown"
        current_conversation_id = "unknown"

        open_tools: dict[str, dict[str, Any]] = {}

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

                    ts = parse_timestamp(entry.get("timestamp"))
                    if ts is None:
                        continue

                    entry_type = entry.get("type")
                    payload = entry.get("payload")
                    if not isinstance(payload, dict):
                        payload = {}

                    if entry_type == "session_meta":
                        session_id = payload.get("id")
                        if session_id:
                            thread_id = str(session_id)
                        continue

                    if entry_type == "turn_context":
                        model = payload.get("model")
                        if model:
                            context_model = str(model)

                        cwd = payload.get("cwd")
                        if cwd:
                            context_cwd = str(cwd)
                            if first_known_cwd == "unknown":
                                first_known_cwd = context_cwd

                        if payload.get("sandbox_policy") is not None:
                            context_sandbox_mode = normalize_sandbox_mode(payload.get("sandbox_policy"))

                        approval = payload.get("approval_policy")
                        if approval:
                            context_approval_policy = str(approval)

                        file_rows.append(
                            AuditEventRow(
                                timestamp=ts,
                                event_type="turn_context",
                                thread_id=thread_id,
                                conversation_id=current_conversation_id,
                                query_id=current_query_id,
                                query_index=query_index if query_index > 0 else None,
                                model=context_model,
                                cwd=context_cwd,
                                sandbox_mode=context_sandbox_mode,
                                approval_policy=context_approval_policy,
                                session_file=str(file_path),
                            )
                        )
                        continue

                    if entry_type == "event_msg":
                        payload_type = payload.get("type")
                        if payload_type == "user_message":
                            query_index += 1
                            current_query_id = f"{thread_id}:q{query_index}"
                            current_conversation_id = current_query_id

                            message_text = str(payload.get("message") or "").strip()
                            if not first_query_text and message_text:
                                first_query_text = message_text

                            file_rows.append(
                                AuditEventRow(
                                    timestamp=ts,
                                    event_type="user_message",
                                    thread_id=thread_id,
                                    conversation_id=current_conversation_id,
                                    query_id=current_query_id,
                                    query_index=query_index,
                                    model=context_model,
                                    cwd=context_cwd,
                                    sandbox_mode=context_sandbox_mode,
                                    approval_policy=context_approval_policy,
                                    session_file=str(file_path),
                                    message_role="user",
                                    message_text=message_text,
                                    query_text=message_text,
                                )
                            )
                            continue

                        if payload_type == "token_count":
                            info = payload.get("info")
                            if not isinstance(info, dict):
                                continue
                            last_usage = info.get("last_token_usage")
                            if not isinstance(last_usage, dict):
                                continue

                            input_tokens = coerce_int(last_usage.get("input_tokens"))
                            output_tokens = coerce_int(last_usage.get("output_tokens"))
                            cached_input_tokens = coerce_int(last_usage.get("cached_input_tokens"))
                            reasoning_output_tokens = coerce_int(last_usage.get("reasoning_output_tokens"))
                            total_tokens = coerce_int(last_usage.get("total_tokens"))
                            if total_tokens is None:
                                total_tokens = (input_tokens or 0) + (output_tokens or 0)

                            file_rows.append(
                                AuditEventRow(
                                    timestamp=ts,
                                    event_type="token_count",
                                    thread_id=thread_id,
                                    conversation_id=current_conversation_id,
                                    query_id=current_query_id,
                                    query_index=query_index if query_index > 0 else None,
                                    model=context_model,
                                    cwd=context_cwd,
                                    sandbox_mode=context_sandbox_mode,
                                    approval_policy=context_approval_policy,
                                    session_file=str(file_path),
                                    input_tokens=input_tokens,
                                    output_tokens=output_tokens,
                                    cached_input_tokens=cached_input_tokens,
                                    reasoning_output_tokens=reasoning_output_tokens,
                                    total_tokens=total_tokens,
                                )
                            )
                            continue

                    if entry_type == "response_item":
                        payload_type = payload.get("type")

                        if payload_type == "message":
                            role = str(payload.get("role") or "assistant")
                            message_text = extract_response_message_text(payload)
                            if not message_text:
                                continue

                            if role == "user":
                                query_index += 1
                                current_query_id = f"{thread_id}:q{query_index}"
                                current_conversation_id = current_query_id
                                if not first_query_text and message_text:
                                    first_query_text = message_text

                            file_rows.append(
                                AuditEventRow(
                                    timestamp=ts,
                                    event_type="user_message",
                                    thread_id=thread_id,
                                    conversation_id=current_conversation_id,
                                    query_id=current_query_id,
                                    query_index=query_index if query_index > 0 else None,
                                    model=context_model,
                                    cwd=context_cwd,
                                    sandbox_mode=context_sandbox_mode,
                                    approval_policy=context_approval_policy,
                                    session_file=str(file_path),
                                    message_role=role,
                                    message_text=message_text,
                                    query_text=message_text if role == "user" else None,
                                )
                            )
                            continue

                        if payload_type == "function_call":
                            call_id = str(payload.get("call_id") or "").strip()
                            if not call_id:
                                continue

                            open_tools[call_id] = {
                                "tool_name": str(payload.get("name") or "unknown_tool"),
                                "start_ts": ts,
                                "thread_id": thread_id,
                                "conversation_id": current_conversation_id,
                                "query_id": current_query_id,
                                "query_index": query_index if query_index > 0 else None,
                                "model": context_model,
                                "cwd": context_cwd,
                                "sandbox_mode": context_sandbox_mode,
                                "approval_policy": context_approval_policy,
                                "session_file": str(file_path),
                            }
                            continue

                        if payload_type == "function_call_output":
                            call_id = str(payload.get("call_id") or "").strip()
                            if not call_id:
                                continue

                            start_info = open_tools.pop(call_id, None)
                            if not start_info:
                                continue

                            start_ts = start_info["start_ts"]
                            start_ms = int(start_ts.timestamp() * 1000)
                            end_ms = int(ts.timestamp() * 1000)
                            duration_ms = parse_tool_duration_ms(payload.get("output"))
                            if duration_ms is None:
                                duration_ms = max(0, end_ms - start_ms)

                            file_rows.append(
                                AuditEventRow(
                                    timestamp=ts,
                                    event_type="tool_call",
                                    thread_id=str(start_info["thread_id"]),
                                    conversation_id=str(start_info["conversation_id"]),
                                    query_id=str(start_info["query_id"]),
                                    query_index=start_info.get("query_index"),
                                    model=str(start_info["model"]),
                                    cwd=str(start_info["cwd"]),
                                    sandbox_mode=str(start_info["sandbox_mode"]),
                                    approval_policy=str(start_info["approval_policy"]),
                                    session_file=str(start_info["session_file"]),
                                    tool_name=str(start_info["tool_name"]),
                                    tool_call_id=call_id,
                                    tool_start_epoch_ms=start_ms,
                                    tool_end_epoch_ms=end_ms,
                                    tool_duration_ms=duration_ms,
                                )
                            )
                            continue

        except OSError:
            continue

        for call_id, start_info in open_tools.items():
            start_ts = start_info["start_ts"]
            start_ms = int(start_ts.timestamp() * 1000)
            file_rows.append(
                AuditEventRow(
                    timestamp=start_ts,
                    event_type="tool_call",
                    thread_id=str(start_info["thread_id"]),
                    conversation_id=str(start_info["conversation_id"]),
                    query_id=str(start_info["query_id"]),
                    query_index=start_info.get("query_index"),
                    model=str(start_info["model"]),
                    cwd=str(start_info["cwd"]),
                    sandbox_mode=str(start_info["sandbox_mode"]),
                    approval_policy=str(start_info["approval_policy"]),
                    session_file=str(start_info["session_file"]),
                    tool_name=str(start_info["tool_name"]),
                    tool_call_id=call_id,
                    tool_start_epoch_ms=start_ms,
                )
            )

        thread_label = thread_title_map.get(thread_id, "").strip()
        if not thread_label:
            thread_label = make_thread_label(
                first_query_text=first_query_text,
                thread_id=thread_id,
                cwd=first_known_cwd,
            )
        for row in file_rows:
            row.thread_label = thread_label
        rows.extend(file_rows)

    rows.sort(key=lambda item: item.timestamp)
    return rows


def _csv_value(value: Any) -> str | int:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return value
    return str(value)


def write_csv_atomic(csv_path: Path, rows: list[AuditEventRow]) -> None:
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
                    "event_type": row.event_type,
                    "thread_id": _csv_value(row.thread_id),
                    "thread_label": _csv_value(row.thread_label),
                    "conversation_id": _csv_value(row.conversation_id),
                    "query_id": _csv_value(row.query_id),
                    "query_index": _csv_value(row.query_index),
                    "model": _csv_value(row.model),
                    "cwd": _csv_value(row.cwd),
                    "sandbox_mode": _csv_value(row.sandbox_mode),
                    "approval_policy": _csv_value(row.approval_policy),
                    "session_file": _csv_value(row.session_file),
                    "message_role": _csv_value(row.message_role),
                    "message_text": _csv_value(row.message_text),
                    "query_text": _csv_value(row.query_text),
                    "tool_name": _csv_value(row.tool_name),
                    "tool_call_id": _csv_value(row.tool_call_id),
                    "tool_start_epoch_ms": _csv_value(row.tool_start_epoch_ms),
                    "tool_end_epoch_ms": _csv_value(row.tool_end_epoch_ms),
                    "tool_duration_ms": _csv_value(row.tool_duration_ms),
                    "input_tokens": _csv_value(row.input_tokens),
                    "output_tokens": _csv_value(row.output_tokens),
                    "cached_input_tokens": _csv_value(row.cached_input_tokens),
                    "reasoning_output_tokens": _csv_value(row.reasoning_output_tokens),
                    "total_tokens": _csv_value(row.total_tokens),
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
        rows = extract_event_rows(self.sessions_dir)
        write_csv_atomic(self.csv_path, rows)

        message: str | None = None
        if not self.sessions_dir.exists():
            message = f"Sessions directory does not exist: {self.sessions_dir}"
        elif not rows:
            message = "No supported events found in sessions logs."

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
    server_version = "ModelAuditLocalApp/2.0"

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
