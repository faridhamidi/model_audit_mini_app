"""Optimization opportunity detection for token usage data."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

try:
    from .audit_constants import NUMERIC_PATTERN, QUERY_INDEX_PATTERN, SPACE_PATTERN, UUID_PATTERN
    from .audit_types import AuditEventRow
    from .audit_utils import as_utc_iso
except ImportError:  # pragma: no cover - support direct script execution
    from audit_constants import NUMERIC_PATTERN, QUERY_INDEX_PATTERN, SPACE_PATTERN, UUID_PATTERN
    from audit_types import AuditEventRow
    from audit_utils import as_utc_iso


def _normalize_query_signature(text: str) -> str:
    normalized = text.strip().lower()
    if not normalized:
        return ""
    normalized = UUID_PATTERN.sub("<id>", normalized)
    normalized = NUMERIC_PATTERN.sub("<num>", normalized)
    normalized = SPACE_PATTERN.sub(" ", normalized)
    return normalized.strip()


def _query_index_for_row(row: AuditEventRow) -> int | None:
    if isinstance(row.query_index, int) and row.query_index > 0:
        return row.query_index
    query_id = str(row.query_id or "")
    match = QUERY_INDEX_PATTERN.search(query_id)
    if not match:
        return None
    try:
        value = int(match.group(1))
    except ValueError:
        return None
    return value if value > 0 else None


def _mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _stddev(values: list[float], mean_value: float) -> float:
    if not values:
        return 0.0
    return (_mean([(value - mean_value) ** 2 for value in values])) ** 0.5


def _regression_slope(values: list[float]) -> float:
    n = len(values)
    if n < 2:
        return 0.0
    xs = [float(index + 1) for index in range(n)]
    x_mean = _mean(xs)
    y_mean = _mean(values)
    numerator = 0.0
    denominator = 0.0
    for index in range(n):
        dx = xs[index] - x_mean
        numerator += dx * (values[index] - y_mean)
        denominator += dx * dx
    if denominator == 0.0:
        return 0.0
    return numerator / denominator


def _percentile(values: list[int], percentile: int) -> int:
    if not values:
        return 0
    if percentile <= 0:
        return min(values)
    if percentile >= 100:
        return max(values)
    ordered = sorted(values)
    index = int((percentile / 100) * len(ordered))
    index = max(0, min(index, len(ordered) - 1))
    return ordered[index]


def _opportunity_severity(estimated_token_savings: int) -> str:
    if estimated_token_savings >= 5000:
        return "high"
    if estimated_token_savings >= 1500:
        return "medium"
    return "low"


def build_optimization_report(rows: list[AuditEventRow], *, generated_at_utc: str) -> dict[str, Any]:
    thread_label_by_id: dict[str, str] = {}
    for row in rows:
        thread_id = str(row.thread_id or "unknown")
        thread_label = str(row.thread_label or "").strip()
        if thread_id and thread_label and thread_id not in thread_label_by_id:
            thread_label_by_id[thread_id] = thread_label

    token_rows = [row for row in rows if row.event_type == "token_count"]
    query_rows = [row for row in rows if row.event_type == "user_message"]

    query_total_tokens: dict[str, int] = {}
    thread_query_input_tokens: dict[str, dict[int, int]] = {}
    for row in token_rows:
        query_id = str(row.query_id or "").strip()
        if query_id and query_id != "unknown":
            query_total_tokens[query_id] = query_total_tokens.get(query_id, 0) + max(0, int(row.total_tokens or 0))

        query_index = _query_index_for_row(row)
        if query_index is None:
            continue
        thread_id = str(row.thread_id or "unknown")
        if thread_id not in thread_query_input_tokens:
            thread_query_input_tokens[thread_id] = {}
        thread_map = thread_query_input_tokens[thread_id]
        thread_map[query_index] = thread_map.get(query_index, 0) + max(0, int(row.input_tokens or 0))

    query_meta: dict[str, dict[str, Any]] = {}
    for row in query_rows:
        query_id = str(row.query_id or "").strip()
        if not query_id or query_id == "unknown":
            continue
        query_text = str(row.query_text or row.message_text or "").strip()
        if not query_text:
            continue
        if query_id in query_meta:
            continue
        query_meta[query_id] = {
            "query_text": query_text,
            "thread_id": str(row.thread_id or "unknown"),
            "cwd": str(row.cwd or "unknown"),
        }

    opportunities: list[dict[str, Any]] = []

    repeat_groups: dict[str, dict[str, Any]] = {}
    for query_id, meta in query_meta.items():
        signature = _normalize_query_signature(str(meta["query_text"]))
        if not signature:
            continue
        total_tokens = int(query_total_tokens.get(query_id, 0))
        if total_tokens <= 0:
            continue
        group = repeat_groups.setdefault(
            signature,
            {
                "occurrences": 0,
                "total_tokens": 0,
                "max_single_tokens": 0,
                "query_text": str(meta["query_text"]),
                "workspaces": set(),
                "threads": set(),
            },
        )
        group["occurrences"] += 1
        group["total_tokens"] += total_tokens
        group["max_single_tokens"] = max(int(group["max_single_tokens"]), total_tokens)
        group["workspaces"].add(str(meta["cwd"] or "unknown"))
        group["threads"].add(str(meta["thread_id"] or "unknown"))

    repeat_candidates: list[dict[str, Any]] = []
    for signature, group in repeat_groups.items():
        occurrences = int(group["occurrences"])
        if occurrences < 3:
            continue
        total_tokens = int(group["total_tokens"])
        avoidable_tokens = total_tokens - int(group["max_single_tokens"])
        if avoidable_tokens <= 0:
            continue
        repeat_candidates.append(
            {
                "signature": signature,
                "signature_preview": str(group["query_text"])[:120],
                "occurrences": occurrences,
                "total_tokens": total_tokens,
                "avoidable_tokens": avoidable_tokens,
                "workspace_count": len(group["workspaces"]),
                "thread_count": len(group["threads"]),
            }
        )

    repeat_candidates.sort(key=lambda item: (-int(item["avoidable_tokens"]), -int(item["occurrences"])))
    if repeat_candidates:
        top_repeats = repeat_candidates[:3]
        repeat_savings = sum(int(item["avoidable_tokens"]) for item in top_repeats)
        opportunities.append(
            {
                "id": "repeat_query_waste",
                "category": "query_efficiency",
                "severity": _opportunity_severity(repeat_savings),
                "title": "Repeated prompts are driving avoidable token spend",
                "estimated_token_savings": repeat_savings,
                "confidence": "high",
                "evidence": {
                    "repeat_signature_count": len(repeat_candidates),
                    "top_signatures": top_repeats,
                },
                "actions": [
                    "Template repeated prompts and reuse a stable shared prompt instead of retyping variants.",
                    "Move recurring setup context into a compact reusable preamble to shrink repeated input tokens.",
                    "Consolidate duplicate prompt loops across workspaces into one reusable workflow.",
                ],
            }
        )

    context_candidates: list[dict[str, Any]] = []
    for thread_id, index_map in thread_query_input_tokens.items():
        ordered = [value for _, value in sorted(index_map.items()) if value >= 0]
        if len(ordered) < 6:
            continue

        rolling: list[float] = []
        for idx in range(len(ordered)):
            start_idx = max(0, idx - 4)
            window_values = [float(value) for value in ordered[start_idx : idx + 1]]
            rolling.append(_mean(window_values))

        slope = _regression_slope(rolling[-10:])
        midpoint = max(1, len(rolling) // 2)
        early_mean = _mean(rolling[:midpoint])
        late_mean = _mean(rolling[midpoint:])
        latest = rolling[-1]

        if slope < 25.0:
            continue
        if latest < 300.0:
            continue
        if late_mean <= (early_mean * 1.2):
            continue

        estimated_savings = int(max(0.0, late_mean - early_mean) * max(1, len(ordered) // 2))
        if estimated_savings <= 0:
            continue

        context_candidates.append(
            {
                "thread_id": thread_id,
                "thread_label": thread_label_by_id.get(thread_id, ""),
                "query_count": len(ordered),
                "slope": round(slope, 3),
                "latest_rolling_input_tokens": int(round(latest)),
                "estimated_token_savings": estimated_savings,
            }
        )

    context_candidates.sort(key=lambda item: (-int(item["estimated_token_savings"]), -float(item["slope"])))
    if context_candidates:
        top_context = context_candidates[:3]
        context_savings = sum(int(item["estimated_token_savings"]) for item in top_context)
        opportunities.append(
            {
                "id": "context_bloat_threads",
                "category": "context_management",
                "severity": _opportunity_severity(context_savings),
                "title": "Long-running threads show context bloat",
                "estimated_token_savings": context_savings,
                "confidence": "medium",
                "evidence": {
                    "thread_count_flagged": len(context_candidates),
                    "top_threads": top_context,
                },
                "actions": [
                    "Split long threads once rolling input rises sharply to avoid carrying stale context.",
                    "Ask the model to summarize state and continue from the summary in a fresh thread.",
                    "Promote durable facts into lightweight checklists rather than restating full background each turn.",
                ],
            }
        )

    bucket_ms = 60 * 60 * 1000
    bucket_map: dict[int, dict[str, Any]] = {}
    for row in token_rows:
        ts_ms = int(row.timestamp.timestamp() * 1000)
        bucket_ts = (ts_ms // bucket_ms) * bucket_ms
        bucket = bucket_map.setdefault(bucket_ts, {"ts": bucket_ts, "total": 0, "by_workspace": {}, "by_thread": {}})
        total = max(0, int(row.total_tokens or 0))
        bucket["total"] = int(bucket["total"]) + total
        workspace = str(row.cwd or "unknown")
        bucket["by_workspace"][workspace] = int(bucket["by_workspace"].get(workspace, 0)) + total
        thread_id = str(row.thread_id or "unknown")
        bucket["by_thread"][thread_id] = int(bucket["by_thread"].get(thread_id, 0)) + total

    sorted_buckets = [bucket_map[key] for key in sorted(bucket_map)]
    bucket_totals = [int(item["total"]) for item in sorted_buckets]
    p90 = _percentile(bucket_totals, 90)
    spike_events: list[dict[str, Any]] = []
    for idx in range(12, len(sorted_buckets)):
        history = [int(value["total"]) for value in sorted_buckets[idx - 12 : idx]]
        mean_history = _mean([float(value) for value in history])
        std_history = _stddev([float(value) for value in history], mean_history)
        current_total = int(sorted_buckets[idx]["total"])
        z_score = 0.0
        if std_history > 0:
            z_score = (current_total - mean_history) / std_history
        elif current_total > mean_history:
            z_score = 999.0

        if z_score < 3.0:
            continue
        if current_total < p90:
            continue
        if current_total < 500:
            continue

        workspace_items = sorted(
            sorted_buckets[idx]["by_workspace"].items(),
            key=lambda item: int(item[1]),
            reverse=True,
        )
        thread_items = sorted(
            sorted_buckets[idx]["by_thread"].items(),
            key=lambda item: int(item[1]),
            reverse=True,
        )
        top_workspace = workspace_items[0] if workspace_items else ("unknown", 0)
        top_thread = thread_items[0] if thread_items else ("unknown", 0)
        spike_events.append(
            {
                "bucket_utc": datetime.fromtimestamp(
                    int(sorted_buckets[idx]["ts"]) / 1000, tz=timezone.utc
                ).isoformat().replace("+00:00", "Z"),
                "total_tokens": current_total,
                "baseline_mean_tokens": int(round(mean_history)),
                "z_score": round(z_score, 2),
                "top_workspace": str(top_workspace[0]),
                "top_thread_id": str(top_thread[0]),
                "top_thread_label": thread_label_by_id.get(str(top_thread[0]), ""),
                "excess_tokens": max(0, int(round(current_total - mean_history))),
            }
        )

    if spike_events:
        spike_savings = int(sum(int(item["excess_tokens"]) * 0.2 for item in spike_events))
        if spike_savings > 0:
            opportunities.append(
                {
                    "id": "token_spike_guardrails",
                    "category": "burst_control",
                    "severity": _opportunity_severity(spike_savings),
                    "title": "Burst windows indicate preventable token spikes",
                    "estimated_token_savings": spike_savings,
                    "confidence": "medium",
                    "evidence": {
                        "spike_count": len(spike_events),
                        "top_spikes": spike_events[:5],
                    },
                    "actions": [
                        "Set a per-hour soft token budget and pause low-priority threads after budget breach.",
                        "Batch similar asks inside one prompt to avoid duplicate high-load windows.",
                        "Run heavy analysis prompts during quieter periods to reduce concurrent context inflation.",
                    ],
                }
            )

    opportunities.sort(key=lambda item: (-int(item["estimated_token_savings"]), item["id"]))
    for idx, opportunity in enumerate(opportunities, start=1):
        opportunity["priority"] = idx

    time_window = {"start_utc": "", "end_utc": ""}
    if rows:
        time_window = {"start_utc": as_utc_iso(rows[0].timestamp), "end_utc": as_utc_iso(rows[-1].timestamp)}

    return {
        "status": "ok",
        "generated_at_utc": generated_at_utc,
        "time_window": time_window,
        "summary": {
            "opportunity_count": len(opportunities),
            "estimated_total_token_savings": sum(int(item["estimated_token_savings"]) for item in opportunities),
            "top_opportunity_id": opportunities[0]["id"] if opportunities else "",
            "token_row_count": len(token_rows),
            "query_row_count": len(query_rows),
        },
        "opportunities": opportunities,
    }
