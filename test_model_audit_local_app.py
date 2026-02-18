from __future__ import annotations

from pathlib import Path

from model_audit_mini_app.model_audit_local_app import (
    CSV_HEADERS,
    extract_turn_rows,
    parse_timestamp,
    write_csv_atomic,
)


def test_parse_timestamp_accepts_zulu() -> None:
    ts = parse_timestamp("2026-02-17T05:00:00Z")
    assert ts is not None
    assert ts.isoformat().startswith("2026-02-17T05:00:00")


def test_extract_turn_rows_filters_invalid_lines(tmp_path: Path) -> None:
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    log_file = sessions / "rollout.jsonl"
    log_file.write_text(
        "\n".join(
            [
                '{"type":"turn_context","timestamp":"2026-02-17T01:02:03Z","payload":{"model":"gpt-5.3-codex","cwd":"/repo","sandbox_policy":{"mode":"read-only"},"approval_policy":"never"}}',
                '{"type":"turn_context","timestamp":"2026-02-17T01:03:03Z","payload":{"cwd":"/repo"}}',
                '{"type":"turn_context","timestamp":"bad-ts","payload":{"model":"gpt-5.3-codex"}}',
                '{"type":"message","timestamp":"2026-02-17T01:04:03Z","payload":{"model":"ignored"}}',
                '{bad-json',
            ]
        ),
        encoding="utf-8",
    )

    rows = extract_turn_rows(sessions)
    assert len(rows) == 1
    row = rows[0]
    assert row.model == "gpt-5.3-codex"
    assert row.cwd == "/repo"
    assert row.sandbox_mode == "read-only"
    assert row.approval_policy == "never"
    assert str(log_file) == row.session_file


def test_write_csv_atomic_outputs_strict_schema(tmp_path: Path) -> None:
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    log_file = sessions / "rollout.jsonl"
    log_file.write_text(
        '{"type":"turn_context","timestamp":"2026-02-17T01:02:03Z","payload":{"model":"gpt-5.3-codex","cwd":"/repo","sandbox_policy":{"type":"workspace-write"},"approval_policy":"on-request"}}\n',
        encoding="utf-8",
    )

    rows = extract_turn_rows(sessions)
    assert len(rows) == 1

    csv_path = tmp_path / "model_audit_data.csv"
    write_csv_atomic(csv_path, rows)

    text = csv_path.read_text(encoding="utf-8")
    lines = text.splitlines()
    assert lines
    assert lines[0].split(",") == CSV_HEADERS

    cols = lines[1].split(",")
    assert cols[2] == "gpt-5.3-codex"
    assert cols[3] == "/repo"
    assert cols[4] == "workspace-write"
    assert cols[5] == "on-request"
