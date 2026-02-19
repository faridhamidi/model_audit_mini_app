from __future__ import annotations

import csv
from pathlib import Path

from model_audit_mini_app import model_audit_local_app as app_module
from model_audit_mini_app.model_audit_local_app import (
    CSV_HEADERS,
    extract_event_rows,
    load_thread_title_map,
    parse_timestamp,
    write_csv_atomic,
)


def test_parse_timestamp_accepts_zulu() -> None:
    ts = parse_timestamp("2026-02-17T05:00:00Z")
    assert ts is not None
    assert ts.isoformat().startswith("2026-02-17T05:00:00")


def test_extract_event_rows_turn_token_and_tool_attribution(tmp_path: Path) -> None:
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    log_file = sessions / "rollout.jsonl"
    log_file.write_text(
        "\n".join(
            [
                '{"type":"session_meta","timestamp":"2026-02-17T01:00:00Z","payload":{"id":"thread-123"}}',
                '{"type":"turn_context","timestamp":"2026-02-17T01:00:01Z","payload":{"model":"gpt-5.3-codex","cwd":"/repo","sandbox_policy":{"mode":"read-only"},"approval_policy":"never"}}',
                '{"type":"event_msg","timestamp":"2026-02-17T01:00:02Z","payload":{"type":"user_message","message":"analyze this"}}',
                '{"type":"event_msg","timestamp":"2026-02-17T01:00:03Z","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":100,"cached_input_tokens":40,"output_tokens":20,"reasoning_output_tokens":10,"total_tokens":120}}}}',
                '{"type":"response_item","timestamp":"2026-02-17T01:00:04Z","payload":{"type":"function_call","name":"shell","call_id":"call_1"}}',
                '{"type":"response_item","timestamp":"2026-02-17T01:00:05Z","payload":{"type":"function_call_output","call_id":"call_1","output":"{\\"metadata\\":{\\"duration_seconds\\":0.5}}"}}',
            ]
        ),
        encoding="utf-8",
    )

    rows = extract_event_rows(sessions)
    assert len(rows) == 4

    turn = next(r for r in rows if r.event_type == "turn_context")
    user_msg = next(r for r in rows if r.event_type == "user_message")
    token = next(r for r in rows if r.event_type == "token_count")
    tool = next(r for r in rows if r.event_type == "tool_call")

    assert turn.thread_id == "thread-123"
    assert turn.model == "gpt-5.3-codex"
    assert turn.cwd == "/repo"
    assert turn.sandbox_mode == "read-only"
    assert turn.approval_policy == "never"

    assert user_msg.query_id == "thread-123:q1"
    assert user_msg.conversation_id == "thread-123:q1"
    assert user_msg.query_text == "analyze this"

    assert token.query_id == "thread-123:q1"
    assert token.input_tokens == 100
    assert token.cached_input_tokens == 40
    assert token.output_tokens == 20
    assert token.reasoning_output_tokens == 10
    assert token.total_tokens == 120

    assert tool.tool_name == "shell"
    assert tool.tool_call_id == "call_1"
    assert tool.tool_duration_ms == 500


def test_extract_event_rows_fallback_thread_and_malformed_lines(tmp_path: Path) -> None:
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    log_file = sessions / "rollout-file-stem.jsonl"
    log_file.write_text(
        "\n".join(
            [
                '{"type":"event_msg","timestamp":"2026-02-17T01:02:03Z","payload":{"type":"user_message","message":"q1"}}',
                '{"type":"event_msg","timestamp":"2026-02-17T01:02:04Z","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":10,"output_tokens":5}}}}',
                '{bad-json',
                '{"type":"event_msg","timestamp":"bad-ts","payload":{"type":"user_message","message":"ignored"}}',
            ]
        ),
        encoding="utf-8",
    )

    rows = extract_event_rows(sessions)
    assert len(rows) == 2

    user = next(r for r in rows if r.event_type == "user_message")
    token = next(r for r in rows if r.event_type == "token_count")

    assert user.thread_id == "rollout-file-stem"
    assert user.query_id == "rollout-file-stem:q1"
    assert token.total_tokens == 15


def test_extract_event_rows_two_queries_deterministic_attribution(tmp_path: Path) -> None:
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    log_file = sessions / "rollout.jsonl"
    log_file.write_text(
        "\n".join(
            [
                '{"type":"session_meta","timestamp":"2026-02-17T01:00:00Z","payload":{"id":"thread-x"}}',
                '{"type":"turn_context","timestamp":"2026-02-17T01:00:01Z","payload":{"model":"gpt-5.3-codex","cwd":"/repo-a","sandbox_policy":{"type":"workspace-write"},"approval_policy":"on-request"}}',
                '{"type":"event_msg","timestamp":"2026-02-17T01:00:02Z","payload":{"type":"user_message","message":"first query"}}',
                '{"type":"event_msg","timestamp":"2026-02-17T01:00:03Z","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":50,"output_tokens":10,"total_tokens":60}}}}',
                '{"type":"turn_context","timestamp":"2026-02-17T01:00:04Z","payload":{"model":"gpt-5.3-codex","cwd":"/repo-b","sandbox_policy":{"type":"workspace-write"},"approval_policy":"on-request"}}',
                '{"type":"event_msg","timestamp":"2026-02-17T01:00:05Z","payload":{"type":"user_message","message":"second query"}}',
                '{"type":"event_msg","timestamp":"2026-02-17T01:00:06Z","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":30,"output_tokens":10,"total_tokens":40}}}}',
            ]
        ),
        encoding="utf-8",
    )

    rows = extract_event_rows(sessions)
    token_rows = [r for r in rows if r.event_type == "token_count"]

    assert len(token_rows) == 2
    by_query = {r.query_id: r.total_tokens for r in token_rows}
    assert by_query["thread-x:q1"] == 60
    assert by_query["thread-x:q2"] == 40

    by_workspace = {}
    for row in token_rows:
        by_workspace[row.cwd] = by_workspace.get(row.cwd, 0) + (row.total_tokens or 0)
    assert by_workspace["/repo-a"] == 60
    assert by_workspace["/repo-b"] == 40


def test_load_thread_title_map_reads_titles(tmp_path: Path) -> None:
    path = tmp_path / "global-state.json"
    path.write_text(
        '{"thread-titles":{"titles":{"abc":"Friendly Thread","x":""},"order":["abc"]}}',
        encoding="utf-8",
    )
    titles = load_thread_title_map(path)
    assert titles == {"abc": "Friendly Thread"}


def test_extract_event_rows_prefers_global_thread_title(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(app_module, "load_thread_title_map", lambda: {"thread-123": "Readable Thread"})

    sessions = tmp_path / "sessions"
    sessions.mkdir()
    log_file = sessions / "rollout.jsonl"
    log_file.write_text(
        "\n".join(
            [
                '{"type":"session_meta","timestamp":"2026-02-17T01:00:00Z","payload":{"id":"thread-123"}}',
                '{"type":"turn_context","timestamp":"2026-02-17T01:00:01Z","payload":{"model":"gpt-5.3-codex","cwd":"/repo","sandbox_policy":{"mode":"read-only"},"approval_policy":"never"}}',
                '{"type":"event_msg","timestamp":"2026-02-17T01:00:02Z","payload":{"type":"user_message","message":"analyze this"}}',
                '{"type":"event_msg","timestamp":"2026-02-17T01:00:03Z","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":10,"output_tokens":5}}}}',
            ]
        ),
        encoding="utf-8",
    )

    rows = extract_event_rows(sessions)
    assert rows
    assert all(r.thread_label == "Readable Thread" for r in rows)


def test_write_csv_atomic_outputs_strict_schema(tmp_path: Path) -> None:
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    log_file = sessions / "rollout.jsonl"
    log_file.write_text(
        "\n".join(
            [
                '{"type":"session_meta","timestamp":"2026-02-17T01:02:00Z","payload":{"id":"thread-csv"}}',
                '{"type":"turn_context","timestamp":"2026-02-17T01:02:03Z","payload":{"model":"gpt-5.3-codex","cwd":"/repo","sandbox_policy":{"type":"workspace-write"},"approval_policy":"on-request"}}',
                '{"type":"event_msg","timestamp":"2026-02-17T01:02:04Z","payload":{"type":"user_message","message":"hello"}}',
                '{"type":"event_msg","timestamp":"2026-02-17T01:02:05Z","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":11,"output_tokens":7}}}}',
            ]
        ),
        encoding="utf-8",
    )

    rows = extract_event_rows(sessions)
    assert rows

    csv_path = tmp_path / "model_audit_data.csv"
    write_csv_atomic(csv_path, rows)

    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == CSV_HEADERS
        data = list(reader)

    assert len(data) == len(rows)
    token_row = next(r for r in data if r["event_type"] == "token_count")
    assert token_row["thread_id"] == "thread-csv"
    assert token_row["input_tokens"] == "11"
    assert token_row["output_tokens"] == "7"
    assert token_row["total_tokens"] == "18"
    assert token_row["tool_name"] == ""
