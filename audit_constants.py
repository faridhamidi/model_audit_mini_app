"""Shared constants for the local model audit app."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

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
    "total_tokens_raw",
    "total_tokens_recomputed",
    "total_tokens_delta",
    "reconciliation_status",
    "total_tokens",
]

HTML_NAME = "model_audit_dashboard.html"
AUDIT_JSON_NAME = "model_audit_audit.json"
SUMMARY_JSON_NAME = "model_audit_summary.json"
OPPORTUNITIES_JSON_NAME = "model_audit_opportunities.json"
DATA_DIR_NAME = "data"
DATA_CATALOG_NAME = "catalog.json"
CODEX_GLOBAL_STATE_PATH = Path.home() / ".codex" / ".codex-global-state.json"
DEFAULT_MAX_CSV_ROWS = 0
DEFAULT_MAX_RETENTION_DAYS = 31
MAX_QUERY_TEXT_CHARS = 600

ROUTING_CSV_HEADERS = [
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
]

QUERY_CSV_HEADERS = [
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
]

TOKEN_CSV_HEADERS = [
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
    "input_tokens",
    "output_tokens",
    "cached_input_tokens",
    "reasoning_output_tokens",
    "total_tokens_raw",
    "total_tokens_recomputed",
    "total_tokens_delta",
    "reconciliation_status",
    "total_tokens",
]

TOOL_CSV_HEADERS = [
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
    "tool_name",
    "tool_call_id",
    "tool_start_epoch_ms",
    "tool_end_epoch_ms",
    "tool_duration_ms",
]

DATASET_SPECS: dict[str, dict[str, Any]] = {
    "routing_context": {
        "event_type": "turn_context",
        "file_name": "routing_context.csv",
        "description": "Routing policy snapshots (model/sandbox/approval per turn context).",
        "headers": ROUTING_CSV_HEADERS,
    },
    "query_messages": {
        "event_type": "user_message",
        "file_name": "query_messages.csv",
        "description": "User query messages and normalized query text.",
        "headers": QUERY_CSV_HEADERS,
    },
    "usage_tokens": {
        "event_type": "token_count",
        "file_name": "usage_tokens.csv",
        "description": "Token telemetry and reconciliation metrics per query.",
        "headers": TOKEN_CSV_HEADERS,
    },
    "tool_calls": {
        "event_type": "tool_call",
        "file_name": "tool_calls.csv",
        "description": "Tool invocations and duration timing.",
        "headers": TOOL_CSV_HEADERS,
    },
}

UUID_PATTERN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", re.IGNORECASE)
NUMERIC_PATTERN = re.compile(r"\b\d+(?:\.\d+)?\b")
SPACE_PATTERN = re.compile(r"\s+")
QUERY_INDEX_PATTERN = re.compile(r":q(\d+)$")
