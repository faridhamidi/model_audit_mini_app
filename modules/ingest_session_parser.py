"""Session-log parser that emits normalized audit rows."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from schema_constants import MAX_QUERY_TEXT_CHARS
from schema_event_types import AuditEventRow
from shared_parsing_utils import (
    compact_text,
    coerce_int,
    derive_thread_id_from_log_file,
    extract_response_message_text,
    list_session_log_files,
    load_thread_title_map,
    make_thread_label,
    normalize_sandbox_mode,
    open_session_log_text,
    parse_timestamp,
    parse_tool_duration_ms,
)


def extract_event_rows(
    sessions_dir: Path,
    *,
    thread_title_loader: Callable[[], dict[str, str]] | None = None,
) -> list[AuditEventRow]:
    rows: list[AuditEventRow] = []
    if not sessions_dir.exists():
        return rows

    thread_title_map = (thread_title_loader or load_thread_title_map)()

    for file_path in list_session_log_files(sessions_dir):
        file_rows: list[AuditEventRow] = []
        session_file_name = file_path.name
        thread_id = derive_thread_id_from_log_file(file_path)
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
            with open_session_log_text(file_path) as handle:
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
                                session_file=session_file_name,
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
                            message_text = compact_text(message_text, MAX_QUERY_TEXT_CHARS)
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
                                    session_file=session_file_name,
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
                            total_tokens_raw = coerce_int(last_usage.get("total_tokens"))

                            # Some compacted/session-summary frames emit a non-zero raw total while all
                            # last-usage components are zero. Those rows are not comparable for raw-vs-recomputed
                            # reconciliation and should not fail A1.
                            is_non_comparable_snapshot = (
                                isinstance(total_tokens_raw, int)
                                and total_tokens_raw > 0
                                and (input_tokens or 0) == 0
                                and (output_tokens or 0) == 0
                                and (cached_input_tokens or 0) == 0
                                and (reasoning_output_tokens or 0) == 0
                            )

                            total_tokens_recomputed: int | None = None
                            if not is_non_comparable_snapshot and (input_tokens is not None or output_tokens is not None):
                                total_tokens_recomputed = (input_tokens or 0) + (output_tokens or 0)

                            total_tokens_delta: int | None = None
                            if total_tokens_raw is not None and total_tokens_recomputed is not None:
                                total_tokens_delta = total_tokens_raw - total_tokens_recomputed

                            if is_non_comparable_snapshot:
                                total_tokens = 0
                            elif total_tokens_recomputed is not None:
                                total_tokens = total_tokens_recomputed
                            else:
                                total_tokens = total_tokens_raw

                            if is_non_comparable_snapshot:
                                reconciliation_status = "non_comparable_snapshot"
                            elif total_tokens_delta is None:
                                reconciliation_status = "insufficient_data"
                            elif total_tokens_delta == 0:
                                reconciliation_status = "match"
                            else:
                                reconciliation_status = "mismatch"

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
                                    session_file=session_file_name,
                                    input_tokens=input_tokens,
                                    output_tokens=output_tokens,
                                    cached_input_tokens=cached_input_tokens,
                                    reasoning_output_tokens=reasoning_output_tokens,
                                    total_tokens_raw=total_tokens_raw,
                                    total_tokens_recomputed=total_tokens_recomputed,
                                    total_tokens_delta=total_tokens_delta,
                                    reconciliation_status=reconciliation_status,
                                    total_tokens=total_tokens,
                                )
                            )
                            continue

                    if entry_type == "response_item":
                        payload_type = payload.get("type")

                        if payload_type == "message":
                            role = str(payload.get("role") or "assistant")
                            if role != "user":
                                continue

                            message_text = extract_response_message_text(payload)
                            if not message_text:
                                continue

                            query_index += 1
                            current_query_id = f"{thread_id}:q{query_index}"
                            current_conversation_id = current_query_id
                            message_text = compact_text(message_text, MAX_QUERY_TEXT_CHARS)
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
                                    session_file=session_file_name,
                                    message_role=role,
                                    message_text=message_text,
                                    query_text=message_text,
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
                                "session_file": session_file_name,
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
