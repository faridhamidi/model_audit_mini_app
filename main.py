#!/usr/bin/env python3
"""Primary CLI and runtime orchestrator for the local model audit app."""

from __future__ import annotations

import argparse
from http.server import ThreadingHTTPServer
from pathlib import Path

try:
    from .audit_core import (
        AUDIT_JSON_NAME,
        DATA_DIR_NAME,
        DEFAULT_MAX_CSV_ROWS,
        DEFAULT_MAX_RETENTION_DAYS,
        HTML_NAME,
        OPPORTUNITIES_JSON_NAME,
        SUMMARY_JSON_NAME,
    )
    from .audit_server import AuditAppContext, AuditDashboardHandler
except ImportError:  # pragma: no cover - support direct script execution
    from audit_core import (  # type: ignore[no-redef]
        AUDIT_JSON_NAME,
        DATA_DIR_NAME,
        DEFAULT_MAX_CSV_ROWS,
        DEFAULT_MAX_RETENTION_DAYS,
        HTML_NAME,
        OPPORTUNITIES_JSON_NAME,
        SUMMARY_JSON_NAME,
    )
    from audit_server import AuditAppContext, AuditDashboardHandler  # type: ignore[no-redef]


def parse_args() -> argparse.Namespace:
    default_reports_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Run local model audit mini app (typed CSV-backed dashboard).",
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
        help=(
            f"Reports directory containing {HTML_NAME}, {AUDIT_JSON_NAME}, {SUMMARY_JSON_NAME}, "
            f"{OPPORTUNITIES_JSON_NAME}, and {DATA_DIR_NAME}/"
        ),
    )
    parser.add_argument(
        "--max-retention-days",
        type=int,
        default=DEFAULT_MAX_RETENTION_DAYS,
        help=(
            "Maximum age of events in days retained in typed CSV datasets "
            f"(default: {DEFAULT_MAX_RETENTION_DAYS})"
        ),
    )
    parser.add_argument(
        "--max-csv-rows",
        type=int,
        default=DEFAULT_MAX_CSV_ROWS,
        help=(
            "Optional hard row cap after age retention (default: 0 = disabled, no row truncation). "
            f"Current default: {DEFAULT_MAX_CSV_ROWS}"
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    sessions_dir = Path(args.sessions_dir).expanduser().resolve()
    reports_dir = Path(args.reports_dir).expanduser().resolve()

    app_context = AuditAppContext(
        sessions_dir=sessions_dir,
        reports_dir=reports_dir,
        max_retention_days=max(0, args.max_retention_days),
        max_csv_rows=max(0, args.max_csv_rows),
    )
    if not app_context.html_path.exists():
        raise SystemExit(f"Missing dashboard template: {app_context.html_path}")

    startup_meta = app_context.refresh_csv()
    print(
        "[model-audit] startup refresh: "
        f"rows={startup_meta['rows_written']} "
        f"trimmed={startup_meta['rows_trimmed_total']} "
        f"retention_days={startup_meta['max_retention_days']} "
        f"estimated_csv_bytes={startup_meta['estimated_csv_bytes']} "
        f"generated_at={startup_meta.get('generated_at_local', startup_meta['generated_at_utc'])} "
        f"timezone={startup_meta.get('timezone', 'local')}"
    )
    print(f"[model-audit] source sessions: {sessions_dir}")
    print(f"[model-audit] data dir: {app_context.data_dir}")

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
