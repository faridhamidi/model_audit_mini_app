"""Usage summary report builder."""

from __future__ import annotations

from datetime import datetime
from typing import Any

try:
    from .audit_types import AuditEventRow
    from .audit_utils import as_local_iso, as_utc_iso, local_timezone_name
except ImportError:  # pragma: no cover - support direct script execution
    from audit_types import AuditEventRow
    from audit_utils import as_local_iso, as_utc_iso, local_timezone_name


def _tool_duration_percentile_ms(sorted_durations: list[int], percentile: int) -> int:
    if not sorted_durations:
        return 0
    if percentile <= 0:
        return sorted_durations[0]
    if percentile >= 100:
        return sorted_durations[-1]

    index = int((percentile / 100) * (len(sorted_durations) - 1))
    return sorted_durations[index]


def _utc_iso_to_local_iso(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return ""
    return as_local_iso(dt)


def build_usage_summary_report(
    rows: list[AuditEventRow],
    *,
    generated_at_utc: str,
    audit_status: str,
) -> dict[str, Any]:
    generated_at_local = _utc_iso_to_local_iso(generated_at_utc) or generated_at_utc
    timezone_name = local_timezone_name()
    if not rows:
        return {
            "status": "ok",
            "generated_at_utc": generated_at_utc,
            "generated_at_local": generated_at_local,
            "timezone": timezone_name,
            "audit_status": audit_status,
            "time_window": {"start_utc": "", "end_utc": ""},
            "time_window_local": {"start_local": "", "end_local": ""},
            "counts": {
                "rows": 0,
                "threads": 0,
                "queries": 0,
                "models": 0,
                "workspaces": 0,
                "tool_calls": 0,
            },
            "totals": {
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "avg_tokens_per_query": 0.0,
            },
            "by_model": [],
            "by_workspace": [],
            "by_thread": [],
            "by_tool": [],
        }

    input_total = 0
    output_total = 0
    total_tokens = 0

    thread_ids: set[str] = set()
    query_ids: set[str] = set()
    model_ids: set[str] = set()
    workspace_ids: set[str] = set()
    tool_call_count = 0

    model_rollup: dict[str, dict[str, Any]] = {}
    workspace_rollup: dict[str, dict[str, Any]] = {}
    thread_rollup: dict[str, dict[str, Any]] = {}
    tool_rollup: dict[str, dict[str, Any]] = {}

    for row in rows:
        thread_id = str(row.thread_id or "unknown")
        model = str(row.model or "unknown")
        cwd = str(row.cwd or "unknown")
        query_id = str(row.query_id or "").strip()

        if thread_id and thread_id != "unknown":
            thread_ids.add(thread_id)
        if model and model != "unknown":
            model_ids.add(model)
        if cwd and cwd != "unknown":
            workspace_ids.add(cwd)
        if query_id and query_id != "unknown":
            query_ids.add(query_id)

        model_stat = model_rollup.setdefault(
            model,
            {"token_count": 0, "tool_call_count": 0, "query_ids": set(), "thread_ids": set()},
        )
        workspace_stat = workspace_rollup.setdefault(
            cwd,
            {"token_count": 0, "tool_call_count": 0, "query_ids": set(), "thread_ids": set()},
        )
        thread_stat = thread_rollup.setdefault(
            thread_id,
            {
                "thread_label": str(row.thread_label or ""),
                "token_count": 0,
                "tool_call_count": 0,
                "query_ids": set(),
                "last_event_utc": "",
                "last_event_local": "",
            },
        )
        if not thread_stat["thread_label"] and row.thread_label:
            thread_stat["thread_label"] = str(row.thread_label)
        thread_stat["last_event_utc"] = as_utc_iso(row.timestamp)
        thread_stat["last_event_local"] = as_local_iso(row.timestamp)

        if query_id and query_id != "unknown":
            model_stat["query_ids"].add(query_id)
            model_stat["thread_ids"].add(thread_id)
            workspace_stat["query_ids"].add(query_id)
            workspace_stat["thread_ids"].add(thread_id)
            thread_stat["query_ids"].add(query_id)

        if row.event_type == "token_count":
            if isinstance(row.input_tokens, int):
                input_total += row.input_tokens
            if isinstance(row.output_tokens, int):
                output_total += row.output_tokens
            if isinstance(row.total_tokens, int):
                total_tokens += row.total_tokens
                model_stat["token_count"] += row.total_tokens
                workspace_stat["token_count"] += row.total_tokens
                thread_stat["token_count"] += row.total_tokens

        if row.event_type == "tool_call":
            tool_call_count += 1
            model_stat["tool_call_count"] += 1
            workspace_stat["tool_call_count"] += 1
            thread_stat["tool_call_count"] += 1

            tool_name = str(row.tool_name or "unknown_tool")
            tool_stat = tool_rollup.setdefault(
                tool_name,
                {
                    "call_count": 0,
                    "total_duration_ms": 0,
                    "rows_without_duration": 0,
                    "durations_ms": [],
                },
            )
            tool_stat["call_count"] += 1
            if isinstance(row.tool_duration_ms, int) and row.tool_duration_ms >= 0:
                tool_stat["total_duration_ms"] += row.tool_duration_ms
                tool_stat["durations_ms"].append(row.tool_duration_ms)
            else:
                tool_stat["rows_without_duration"] += 1

    by_model = [
        {
            "model": model,
            "query_count": len(stat["query_ids"]),
            "thread_count": len(stat["thread_ids"]),
            "tool_call_count": int(stat["tool_call_count"]),
            "token_count": int(stat["token_count"]),
        }
        for model, stat in model_rollup.items()
    ]
    by_model.sort(key=lambda item: (-item["token_count"], -item["query_count"], item["model"]))

    by_workspace = [
        {
            "cwd": cwd,
            "query_count": len(stat["query_ids"]),
            "thread_count": len(stat["thread_ids"]),
            "tool_call_count": int(stat["tool_call_count"]),
            "token_count": int(stat["token_count"]),
        }
        for cwd, stat in workspace_rollup.items()
    ]
    by_workspace.sort(key=lambda item: (-item["token_count"], -item["query_count"], item["cwd"]))

    by_thread = [
        {
            "thread_id": thread_id,
            "thread_label": str(stat["thread_label"] or ""),
            "query_count": len(stat["query_ids"]),
            "tool_call_count": int(stat["tool_call_count"]),
            "token_count": int(stat["token_count"]),
            "last_event_utc": str(stat["last_event_utc"] or ""),
            "last_event_local": str(stat["last_event_local"] or ""),
        }
        for thread_id, stat in thread_rollup.items()
    ]
    by_thread.sort(key=lambda item: (-item["token_count"], -item["query_count"], item["thread_id"]))

    by_tool = []
    for tool_name, stat in tool_rollup.items():
        call_count = int(stat["call_count"])
        total_duration_ms = int(stat["total_duration_ms"])
        durations = sorted(int(value) for value in stat["durations_ms"])
        avg_duration_ms = int(total_duration_ms / call_count) if call_count > 0 else 0
        by_tool.append(
            {
                "tool_name": tool_name,
                "call_count": call_count,
                "total_duration_ms": total_duration_ms,
                "avg_duration_ms": avg_duration_ms,
                "p95_duration_ms": _tool_duration_percentile_ms(durations, 95),
                "rows_without_duration": int(stat["rows_without_duration"]),
            }
        )
    by_tool.sort(key=lambda item: (-item["call_count"], item["tool_name"]))

    start_utc = as_utc_iso(rows[0].timestamp)
    end_utc = as_utc_iso(rows[-1].timestamp)
    start_local = as_local_iso(rows[0].timestamp)
    end_local = as_local_iso(rows[-1].timestamp)
    query_count = len(query_ids)
    avg_tokens_per_query = (total_tokens / query_count) if query_count else 0.0

    return {
        "status": "ok",
        "generated_at_utc": generated_at_utc,
        "generated_at_local": generated_at_local,
        "timezone": timezone_name,
        "audit_status": audit_status,
        "time_window": {"start_utc": start_utc, "end_utc": end_utc},
        "time_window_local": {"start_local": start_local, "end_local": end_local},
        "counts": {
            "rows": len(rows),
            "threads": len(thread_ids),
            "queries": query_count,
            "models": len(model_ids),
            "workspaces": len(workspace_ids),
            "tool_calls": tool_call_count,
        },
        "totals": {
            "input_tokens": input_total,
            "output_tokens": output_total,
            "total_tokens": total_tokens,
            "avg_tokens_per_query": avg_tokens_per_query,
        },
        "by_model": by_model,
        "by_workspace": by_workspace,
        "by_thread": by_thread,
        "by_tool": by_tool,
    }
