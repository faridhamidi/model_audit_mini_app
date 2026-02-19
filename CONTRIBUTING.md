# Contributing

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -U pip
python3 -m pip install -r requirements-dev.txt
```

## Before Opening a PR

1. Run tests: `python3 -m pytest`
2. Keep generated runtime artifacts out of commits (`data/`, `model_audit_*.json`)
3. Update tests when parsing/reporting behavior changes
4. Keep changes scoped and documented in `README.md` when needed

## Coding Notes

- Prefer small, composable functions in the existing modules.
- Keep typed CSV schemas in `audit_constants.py` and related parser logic in `audit_parser.py`.
- Ensure backward-compatible API payloads unless a breaking change is explicitly intended.
