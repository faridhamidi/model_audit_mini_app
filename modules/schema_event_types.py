"""Typed row structures for model audit events."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


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
    total_tokens_raw: int | None = None
    total_tokens_recomputed: int | None = None
    total_tokens_delta: int | None = None
    reconciliation_status: str | None = None
    total_tokens: int | None = None
