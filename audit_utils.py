"""Low-level parsing and normalization helpers."""

from __future__ import annotations

import gzip
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from .audit_constants import CODEX_GLOBAL_STATE_PATH
except ImportError:  # pragma: no cover - support direct script execution
    from audit_constants import CODEX_GLOBAL_STATE_PATH


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    raw = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def as_utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def as_local_iso(dt: datetime) -> str:
    return dt.astimezone().isoformat()


def local_timezone_name(dt: datetime | None = None) -> str:
    ref = dt if dt is not None else datetime.now().astimezone()
    return str(ref.tzname() or "local")


def normalize_sandbox_mode(policy: Any) -> str:
    if isinstance(policy, dict):
        return str(policy.get("type") or policy.get("mode") or "unknown")
    return "unknown"


def coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            if "." in text:
                return int(float(text))
            return int(text)
        except ValueError:
            return None
    return None


def compact_text(value: str | None, max_chars: int) -> str:
    if not value:
        return ""
    normalized = " ".join(value.split())
    if max_chars <= 0:
        return ""
    if len(normalized) <= max_chars:
        return normalized
    if max_chars <= 3:
        return normalized[:max_chars]
    return normalized[: max_chars - 3] + "..."


def extract_response_message_text(payload: dict[str, Any]) -> str:
    content = payload.get("content")
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if not isinstance(item, dict):
                continue
            text = item.get("text")
            if isinstance(text, str) and text.strip():
                parts.append(text)
        return "\n".join(parts).strip()
    text = payload.get("text")
    if isinstance(text, str):
        return text.strip()
    return ""


def parse_tool_duration_ms(output_payload: Any) -> int | None:
    parsed: Any = output_payload
    if isinstance(output_payload, str):
        text = output_payload.strip()
        if text:
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = None

    if not isinstance(parsed, dict):
        return None

    metadata = parsed.get("metadata")
    if isinstance(metadata, dict):
        dur_ms = coerce_int(metadata.get("duration_ms"))
        if dur_ms is not None:
            return max(0, dur_ms)
        dur_seconds = metadata.get("duration_seconds")
        if isinstance(dur_seconds, (int, float)):
            return max(0, int(dur_seconds * 1000))

    dur_ms = coerce_int(parsed.get("duration_ms"))
    if dur_ms is not None:
        return max(0, dur_ms)
    dur_seconds = parsed.get("duration_seconds")
    if isinstance(dur_seconds, (int, float)):
        return max(0, int(dur_seconds * 1000))
    return None


def load_thread_title_map(global_state_path: Path = CODEX_GLOBAL_STATE_PATH) -> dict[str, str]:
    try:
        raw = global_state_path.read_text(encoding="utf-8")
    except OSError:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(payload, dict):
        return {}
    section = payload.get("thread-titles")
    if not isinstance(section, dict):
        return {}
    titles = section.get("titles")
    if not isinstance(titles, dict):
        return {}
    mapped: dict[str, str] = {}
    for key, value in titles.items():
        if not isinstance(key, str):
            continue
        if not isinstance(value, str):
            continue
        title = value.strip()
        if title:
            mapped[key.strip()] = title
    return mapped


def make_thread_label(first_query_text: str, thread_id: str, cwd: str) -> str:
    lines = [line.strip() for line in first_query_text.splitlines() if line.strip()]
    for line in lines:
        low = line.lower()
        if low.startswith("<environment_context>"):
            continue
        if low.startswith("# context from my ide setup"):
            continue
        if low.startswith("## my request for codex"):
            continue
        cleaned = line.lstrip("-*# ").strip()
        if cleaned:
            return cleaned[:72]

    base = Path(cwd).name if cwd and cwd != "unknown" else "thread"
    suffix = thread_id.split("-")[0][:8] if thread_id else "unknown"
    return f"{base}-{suffix}"[:72]


def list_session_log_files(sessions_dir: Path) -> list[Path]:
    files: set[Path] = set()
    files.update(sessions_dir.rglob("*.jsonl"))
    files.update(sessions_dir.rglob("*.jsonl.gz"))
    return sorted(files)


def derive_thread_id_from_log_file(file_path: Path) -> str:
    file_name = file_path.name
    if file_name.endswith(".jsonl.gz"):
        return file_name[: -len(".jsonl.gz")]
    if file_name.endswith(".jsonl"):
        return file_name[: -len(".jsonl")]
    return file_path.stem


def open_session_log_text(file_path: Path):
    if file_path.name.endswith(".gz"):
        return gzip.open(file_path, mode="rt", encoding="utf-8", errors="replace")
    return file_path.open("r", encoding="utf-8", errors="replace")
