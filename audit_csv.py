"""CSV serialization and dataset partitioning helpers."""

from __future__ import annotations

import csv
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

try:
    from .audit_constants import CSV_HEADERS, DATASET_SPECS, DATA_DIR_NAME
    from .audit_types import AuditEventRow
    from .audit_utils import as_utc_iso
except ImportError:  # pragma: no cover - support direct script execution
    from audit_constants import CSV_HEADERS, DATASET_SPECS, DATA_DIR_NAME
    from audit_types import AuditEventRow
    from audit_utils import as_utc_iso


def _csv_value(value: Any) -> str | int:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return value
    return str(value)


def _row_to_csv_dict(row: AuditEventRow) -> dict[str, str | int]:
    return {
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
        "total_tokens_raw": _csv_value(row.total_tokens_raw),
        "total_tokens_recomputed": _csv_value(row.total_tokens_recomputed),
        "total_tokens_delta": _csv_value(row.total_tokens_delta),
        "reconciliation_status": _csv_value(row.reconciliation_status),
        "total_tokens": _csv_value(row.total_tokens),
    }


def trim_rows_for_csv_budget(
    rows: list[AuditEventRow],
    *,
    max_retention_days: int,
    max_rows: int,
) -> tuple[list[AuditEventRow], dict[str, Any]]:
    original_count = len(rows)
    trimmed_by_age_limit = 0
    trimmed_by_row_limit = 0
    retention_cutoff_utc = ""
    latest_event_utc = ""

    effective_rows = rows
    latest_ts: datetime | None = None
    if effective_rows:
        latest_ts = effective_rows[-1].timestamp
        latest_event_utc = as_utc_iso(latest_ts)

    if max_retention_days > 0 and latest_ts is not None:
        cutoff_ts = latest_ts - timedelta(days=max_retention_days)
        retention_cutoff_utc = as_utc_iso(cutoff_ts)
        start_idx = 0
        while start_idx < len(effective_rows) and effective_rows[start_idx].timestamp < cutoff_ts:
            start_idx += 1
        trimmed_by_age_limit = start_idx
        effective_rows = effective_rows[start_idx:]

    if max_rows > 0 and len(effective_rows) > max_rows:
        trimmed_by_row_limit = len(effective_rows) - max_rows
        effective_rows = effective_rows[-max_rows:]

    return (
        effective_rows,
        {
            "original_rows": original_count,
            "rows_after_limits": len(effective_rows),
            "trimmed_by_age_limit": trimmed_by_age_limit,
            "trimmed_by_row_limit": trimmed_by_row_limit,
            "max_retention_days": max_retention_days,
            "latest_event_utc": latest_event_utc,
            "retention_cutoff_utc": retention_cutoff_utc,
        },
    )


def write_csv_atomic(
    csv_path: Path,
    rows: list[AuditEventRow],
    *,
    headers: list[str] | None = None,
) -> None:
    fieldnames = headers or CSV_HEADERS
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
        writer = csv.DictWriter(temp_file, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            row_payload = _row_to_csv_dict(row)
            writer.writerow({name: row_payload.get(name, "") for name in fieldnames})
        temp_path = Path(temp_file.name)

    temp_path.replace(csv_path)


def write_dataset_csvs_atomic(data_dir: Path, rows: list[AuditEventRow]) -> dict[str, dict[str, Any]]:
    data_dir.mkdir(parents=True, exist_ok=True)
    dataset_meta: dict[str, dict[str, Any]] = {}
    for dataset_key, spec in DATASET_SPECS.items():
        event_type = str(spec["event_type"])
        headers = list(spec["headers"])
        file_name = str(spec["file_name"])
        csv_path = data_dir / file_name
        dataset_rows = [row for row in rows if row.event_type == event_type]
        write_csv_atomic(csv_path, dataset_rows, headers=headers)
        dataset_meta[dataset_key] = {
            "key": dataset_key,
            "event_type": event_type,
            "file_name": file_name,
            "description": str(spec["description"]),
            "required_fields": headers,
            "row_count": len(dataset_rows),
            "csv_path": str(csv_path),
            "relative_path": f"/{DATA_DIR_NAME}/{file_name}",
            "csv_bytes": csv_path.stat().st_size if csv_path.exists() else 0,
        }
    return dataset_meta
