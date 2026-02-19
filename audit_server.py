"""HTTP server primitives and app context for the model audit app."""

from __future__ import annotations

import csv
import json
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

try:
    from .audit_core import (
        AUDIT_JSON_NAME,
        DATASET_SPECS,
        DATA_CATALOG_NAME,
        DATA_DIR_NAME,
        DEFAULT_MAX_CSV_ROWS,
        DEFAULT_MAX_RETENTION_DAYS,
        HTML_NAME,
        OPPORTUNITIES_JSON_NAME,
        SUMMARY_JSON_NAME,
        as_local_iso,
        as_utc_iso,
        build_optimization_report,
        build_usage_summary_report,
        extract_event_rows,
        local_timezone_name,
        parse_timestamp,
        trim_rows_for_csv_budget,
        write_dataset_csvs_atomic,
    )
    from .metrics_audit import build_usage_audit_report
except ImportError:  # pragma: no cover - support direct script execution
    from audit_core import (  # type: ignore[no-redef]
        AUDIT_JSON_NAME,
        DATASET_SPECS,
        DATA_CATALOG_NAME,
        DATA_DIR_NAME,
        DEFAULT_MAX_CSV_ROWS,
        DEFAULT_MAX_RETENTION_DAYS,
        HTML_NAME,
        OPPORTUNITIES_JSON_NAME,
        SUMMARY_JSON_NAME,
        as_local_iso,
        as_utc_iso,
        build_optimization_report,
        build_usage_summary_report,
        extract_event_rows,
        local_timezone_name,
        parse_timestamp,
        trim_rows_for_csv_budget,
        write_dataset_csvs_atomic,
    )
    from metrics_audit import build_usage_audit_report  # type: ignore[no-redef]


REFRESH_COOLDOWN_SECONDS = 3


class RefreshCooldownError(RuntimeError):
    def __init__(self, *, retry_after_seconds: float, message: str) -> None:
        super().__init__(message)
        self.retry_after_seconds = max(0.0, float(retry_after_seconds))


class AuditAppContext:
    def __init__(
        self,
        sessions_dir: Path,
        reports_dir: Path,
        *,
        max_retention_days: int = DEFAULT_MAX_RETENTION_DAYS,
        max_csv_rows: int = DEFAULT_MAX_CSV_ROWS,
        refresh_cooldown_seconds: int = REFRESH_COOLDOWN_SECONDS,
    ) -> None:
        self.sessions_dir = sessions_dir
        self.reports_dir = reports_dir
        self.html_path = reports_dir / HTML_NAME
        self.data_dir = reports_dir / DATA_DIR_NAME
        self.data_catalog_path = self.data_dir / DATA_CATALOG_NAME
        self.audit_json_path = reports_dir / AUDIT_JSON_NAME
        self.summary_json_path = reports_dir / SUMMARY_JSON_NAME
        self.opportunities_json_path = reports_dir / OPPORTUNITIES_JSON_NAME
        self.max_retention_days = max_retention_days
        self.max_csv_rows = max_csv_rows
        self.refresh_cooldown_seconds = max(0.0, float(refresh_cooldown_seconds))
        self.last_refresh_meta: dict[str, Any] | None = None
        self._refresh_lock = threading.Lock()
        self._refresh_in_progress = False
        self._last_refresh_completed_monotonic: float | None = None

    def refresh_csv_guarded(self) -> dict[str, Any]:
        now = time.monotonic()
        with self._refresh_lock:
            if self._refresh_in_progress:
                raise RefreshCooldownError(
                    retry_after_seconds=self.refresh_cooldown_seconds,
                    message="Refresh already in progress. Please wait before retrying.",
                )
            if self._last_refresh_completed_monotonic is not None:
                elapsed = now - self._last_refresh_completed_monotonic
                remaining = self.refresh_cooldown_seconds - elapsed
                if remaining > 0:
                    raise RefreshCooldownError(
                        retry_after_seconds=remaining,
                        message=f"Refresh cooldown active. Retry in {int(remaining) + 1}s.",
                    )
            self._refresh_in_progress = True

        try:
            return self.refresh_csv()
        finally:
            with self._refresh_lock:
                self._refresh_in_progress = False
                self._last_refresh_completed_monotonic = time.monotonic()

    def refresh_csv(self) -> dict[str, Any]:
        generated_at = datetime.now(timezone.utc).astimezone()
        generated_at_utc = as_utc_iso(generated_at)
        generated_at_local = as_local_iso(generated_at)
        timezone_name = local_timezone_name(generated_at)
        rows = extract_event_rows(self.sessions_dir)
        rows, trim_stats = trim_rows_for_csv_budget(
            rows,
            max_retention_days=self.max_retention_days,
            max_rows=self.max_csv_rows,
        )
        dataset_meta = write_dataset_csvs_atomic(self.data_dir, rows)
        total_data_bytes = sum(int(item.get("csv_bytes") or 0) for item in dataset_meta.values())

        latest_event_epoch_ms = 0
        latest_event_utc = str(trim_stats.get("latest_event_utc", ""))
        latest_event_local = ""
        if latest_event_utc:
            latest_dt = parse_timestamp(latest_event_utc)
            if latest_dt is not None:
                latest_event_epoch_ms = int(latest_dt.timestamp() * 1000)
                latest_event_local = as_local_iso(latest_dt)

        retention_cutoff_utc = str(trim_stats.get("retention_cutoff_utc", ""))
        retention_cutoff_local = ""
        if retention_cutoff_utc:
            cutoff_dt = parse_timestamp(retention_cutoff_utc)
            if cutoff_dt is not None:
                retention_cutoff_local = as_local_iso(cutoff_dt)

        audit_report = build_usage_audit_report(rows=rows, generated_at_utc=generated_at_utc)
        self.audit_json_path.write_text(
            json.dumps(audit_report, ensure_ascii=True, indent=2),
            encoding="utf-8",
        )
        summary_report = build_usage_summary_report(
            rows=rows,
            generated_at_utc=generated_at_utc,
            audit_status=str(audit_report.get("status", "unknown")),
        )
        self.summary_json_path.write_text(
            json.dumps(summary_report, ensure_ascii=True, indent=2),
            encoding="utf-8",
        )
        opportunities_report = build_optimization_report(rows=rows, generated_at_utc=generated_at_utc)
        self.opportunities_json_path.write_text(
            json.dumps(opportunities_report, ensure_ascii=True, indent=2),
            encoding="utf-8",
        )

        data_catalog = {
            "status": "ok",
            "timezone": timezone_name,
            "generated_at_utc": generated_at_utc,
            "generated_at_local": generated_at_local,
            "latest_event_utc": latest_event_utc,
            "latest_event_local": latest_event_local,
            "latest_event_epoch_ms": latest_event_epoch_ms,
            "source_sessions_dir": str(self.sessions_dir),
            "max_retention_days": self.max_retention_days,
            "retention_cutoff_utc": retention_cutoff_utc,
            "retention_cutoff_local": retention_cutoff_local,
            "datasets": list(dataset_meta.values()),
        }
        self.data_catalog_path.write_text(
            json.dumps(data_catalog, ensure_ascii=True, indent=2),
            encoding="utf-8",
        )

        message: str | None = None
        if not self.sessions_dir.exists():
            message = f"Sessions directory does not exist: {self.sessions_dir}"
        elif not rows:
            message = "No supported events found in sessions logs."

        meta = {
            "status": "ok",
            "rows_written": len(rows),
            "rows_source_total": trim_stats["original_rows"],
            "rows_trimmed_total": trim_stats["trimmed_by_age_limit"] + trim_stats["trimmed_by_row_limit"],
            "rows_trimmed_by_age_limit": trim_stats["trimmed_by_age_limit"],
            "rows_trimmed_by_row_limit": trim_stats["trimmed_by_row_limit"],
            "max_retention_days": self.max_retention_days,
            "timezone": timezone_name,
            "retention_cutoff_utc": retention_cutoff_utc,
            "retention_cutoff_local": retention_cutoff_local,
            "latest_event_utc": trim_stats["latest_event_utc"],
            "latest_event_local": latest_event_local,
            "max_csv_rows": self.max_csv_rows,
            "estimated_csv_bytes": total_data_bytes,
            "generated_at_utc": generated_at_utc,
            "generated_at_local": generated_at_local,
            "source_sessions_dir": str(self.sessions_dir),
            "data_dir": str(self.data_dir),
            "data_catalog_path": str(self.data_catalog_path),
            "audit_json_path": str(self.audit_json_path),
            "summary_json_path": str(self.summary_json_path),
            "opportunities_json_path": str(self.opportunities_json_path),
            "audit_status": str(audit_report.get("status", "unknown")),
            "metrics_version": str(audit_report.get("metrics_version", "unknown")),
            "latest_event_epoch_ms": latest_event_epoch_ms,
            "dataset_rows": {key: int(value["row_count"]) for key, value in dataset_meta.items()},
            "opportunities_count": int(opportunities_report["summary"]["opportunity_count"]),
            "estimated_total_token_savings": int(opportunities_report["summary"]["estimated_total_token_savings"]),
        }
        if message:
            meta["message"] = message
        self.last_refresh_meta = meta
        return meta

    def load_dashboard_html(self) -> str:
        text = self.html_path.read_text(encoding="utf-8")
        refresh_time = ""
        if self.last_refresh_meta:
            refresh_time = str(
                self.last_refresh_meta.get("generated_at_local")
                or self.last_refresh_meta.get("generated_at_utc", "")
            )
        text = text.replace("__SOURCE_SESSIONS_DIR__", str(self.sessions_dir))
        text = text.replace("__DATA_BASE_PATH__", f"/{DATA_DIR_NAME}")
        text = text.replace("__AUDIT_JSON_RELATIVE_PATH__", "/audit.json")
        text = text.replace("__OPPORTUNITIES_JSON_RELATIVE_PATH__", "/opportunities.json")
        text = text.replace("__LAST_REFRESH_LOCAL__", refresh_time)
        return text

    def ensure_data(self) -> dict[str, Any]:
        has_csv = False
        for spec in DATASET_SPECS.values():
            file_name = str(spec["file_name"])
            if (self.data_dir / file_name).exists():
                has_csv = True
                break
        has_core_artifacts = (
            self.data_catalog_path.exists()
            and self.audit_json_path.exists()
            and self.summary_json_path.exists()
            and self.opportunities_json_path.exists()
        )
        if has_csv and has_core_artifacts:
            return self.last_refresh_meta or {"status": "ok"}
        return self.refresh_csv()

    def read_dataset_csv(
        self,
        dataset_file_name: str,
        *,
        start_ms: int | None = None,
        end_ms: int | None = None,
    ) -> bytes:
        csv_path = self.data_dir / dataset_file_name
        if not csv_path.exists():
            raise FileNotFoundError(f"Dataset CSV missing: {csv_path}")
        if start_ms is None and end_ms is None:
            return csv_path.read_bytes()

        with csv_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            fieldnames = list(reader.fieldnames or [])
            output = tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                newline="",
                delete=False,
                dir=str(csv_path.parent),
                prefix=".tmp_model_audit_window_",
                suffix=".csv",
            )
            temp_path = Path(output.name)
            try:
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                for row in reader:
                    ts_text = row.get("timestamp_epoch_ms")
                    if not ts_text:
                        continue
                    try:
                        ts = int(ts_text)
                    except ValueError:
                        continue
                    if start_ms is not None and ts < start_ms:
                        continue
                    if end_ms is not None and ts > end_ms:
                        continue
                    writer.writerow(row)
            finally:
                output.close()

        try:
            payload = temp_path.read_bytes()
        finally:
            temp_path.unlink(missing_ok=True)
        return payload


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

        if parsed.path.startswith(f"/{DATA_DIR_NAME}/"):
            meta = self.app.ensure_data()
            if meta.get("status") != "ok":
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, meta)
                return

            relative = parsed.path[len(f"/{DATA_DIR_NAME}/") :]
            if relative == DATA_CATALOG_NAME:
                body = self.app.data_catalog_path.read_bytes()
                self._send_bytes(HTTPStatus.OK, body, "application/json; charset=utf-8")
                return

            allowed_files = {str(spec["file_name"]) for spec in DATASET_SPECS.values()}
            if relative not in allowed_files:
                self._send_not_found()
                return

            qs = parse_qs(parsed.query)

            def _query_int(name: str) -> int | None:
                raw = qs.get(name, [""])[0].strip()
                if not raw:
                    return None
                try:
                    return int(raw)
                except ValueError as exc:
                    raise ValueError(f"Invalid query parameter '{name}': {raw}") from exc

            try:
                start_ms = _query_int("start_ms")
                end_ms = _query_int("end_ms")
                body = self.app.read_dataset_csv(relative, start_ms=start_ms, end_ms=end_ms)
            except FileNotFoundError:
                self._send_not_found()
                return
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"status": "error", "message": str(exc)})
                return

            self._send_bytes(HTTPStatus.OK, body, "text/csv; charset=utf-8")
            return

        if parsed.path == "/audit.json":
            if not self.app.audit_json_path.exists():
                meta = self.app.ensure_data()
                if meta.get("status") != "ok":
                    self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, meta)
                    return
            body = self.app.audit_json_path.read_bytes()
            self._send_bytes(HTTPStatus.OK, body, "application/json; charset=utf-8")
            return

        if parsed.path == "/summary.json":
            if not self.app.summary_json_path.exists():
                meta = self.app.ensure_data()
                if meta.get("status") != "ok":
                    self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, meta)
                    return
            body = self.app.summary_json_path.read_bytes()
            self._send_bytes(HTTPStatus.OK, body, "application/json; charset=utf-8")
            return

        if parsed.path == "/opportunities.json":
            if not self.app.opportunities_json_path.exists():
                meta = self.app.ensure_data()
                if meta.get("status") != "ok":
                    self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, meta)
                    return
            body = self.app.opportunities_json_path.read_bytes()
            self._send_bytes(HTTPStatus.OK, body, "application/json; charset=utf-8")
            return

        self._send_not_found()

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/refresh":
            try:
                meta = self.app.refresh_csv_guarded()
            except RefreshCooldownError as exc:
                retry_after_seconds = max(1, int(exc.retry_after_seconds + 0.999))
                self._send_json(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    {
                        "status": "error",
                        "message": str(exc),
                        "retry_after_seconds": retry_after_seconds,
                    },
                )
                return
            except Exception as exc:  # noqa: BLE001
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"status": "error", "message": f"Refresh failed: {exc}"},
                )
                return
            meta["refresh_cooldown_seconds"] = int(self.app.refresh_cooldown_seconds)
            self._send_json(HTTPStatus.OK, meta)
            return

        self._send_not_found()
