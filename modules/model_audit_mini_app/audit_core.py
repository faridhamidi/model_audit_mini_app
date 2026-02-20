"""Compatibility export layer for modular audit core components."""

from __future__ import annotations

try:
    from .audit_constants import (
        AUDIT_JSON_NAME,
        CODEX_GLOBAL_STATE_PATH,
        CSV_HEADERS,
        DATASET_SPECS,
        DATA_CATALOG_NAME,
        DATA_DIR_NAME,
        DEFAULT_MAX_CSV_ROWS,
        DEFAULT_MAX_RETENTION_DAYS,
        HTML_NAME,
        MAX_QUERY_TEXT_CHARS,
        OPPORTUNITIES_JSON_NAME,
        QUERY_CSV_HEADERS,
        ROUTING_CSV_HEADERS,
        SUMMARY_JSON_NAME,
        TOKEN_CSV_HEADERS,
        TOOL_CSV_HEADERS,
    )
    from .audit_csv import trim_rows_for_csv_budget, write_csv_atomic, write_dataset_csvs_atomic
    from .audit_optimization_report import build_optimization_report
    from .audit_parser import extract_event_rows
    from .audit_summary_report import build_usage_summary_report
    from .audit_types import AuditEventRow
    from .audit_utils import (
        as_local_iso,
        as_utc_iso,
        coerce_int,
        compact_text,
        derive_thread_id_from_log_file,
        extract_response_message_text,
        list_session_log_files,
        load_thread_title_map,
        local_timezone_name,
        make_thread_label,
        normalize_sandbox_mode,
        open_session_log_text,
        parse_timestamp,
        parse_tool_duration_ms,
    )
except ImportError:  # pragma: no cover - support direct script execution
    from audit_constants import (
        AUDIT_JSON_NAME,
        CODEX_GLOBAL_STATE_PATH,
        CSV_HEADERS,
        DATASET_SPECS,
        DATA_CATALOG_NAME,
        DATA_DIR_NAME,
        DEFAULT_MAX_CSV_ROWS,
        DEFAULT_MAX_RETENTION_DAYS,
        HTML_NAME,
        MAX_QUERY_TEXT_CHARS,
        OPPORTUNITIES_JSON_NAME,
        QUERY_CSV_HEADERS,
        ROUTING_CSV_HEADERS,
        SUMMARY_JSON_NAME,
        TOKEN_CSV_HEADERS,
        TOOL_CSV_HEADERS,
    )
    from audit_csv import trim_rows_for_csv_budget, write_csv_atomic, write_dataset_csvs_atomic
    from audit_optimization_report import build_optimization_report
    from audit_parser import extract_event_rows
    from audit_summary_report import build_usage_summary_report
    from audit_types import AuditEventRow
    from audit_utils import (
        as_local_iso,
        as_utc_iso,
        coerce_int,
        compact_text,
        derive_thread_id_from_log_file,
        extract_response_message_text,
        list_session_log_files,
        load_thread_title_map,
        local_timezone_name,
        make_thread_label,
        normalize_sandbox_mode,
        open_session_log_text,
        parse_timestamp,
        parse_tool_duration_ms,
    )


__all__ = [name for name in globals() if not name.startswith("__")]
