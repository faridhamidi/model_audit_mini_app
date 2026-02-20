# model_audit_mini_app

Local dashboard for auditing Codex session usage: model routing, token usage, tool calls, and optimization opportunities.

## Introduction

The dashboard provides quick visibility into routing patterns, usage trends, and audit signals across your Codex sessions.

### Usage Overview

![Usage dashboard screenshot](docs/screenshots/sc-usage-usage-1.png)

### Model Routing

![Model routing dashboard screenshot](docs/screenshots/sc-modelrouting-1.png)

## Public Repo Notes

This repo is configured to avoid committing runtime artifacts that can include sensitive local metadata (for example local filesystem paths, thread labels, and prompt text).

Ignored generated outputs:
- `reports/data/`
- `reports/model_audit_audit.json`
- `reports/model_audit_summary.json`
- `reports/model_audit_opportunities.json`

## Requirements

- Python 3.10+
- [Codex CLI](https://github.com/openai/codex) with session logs in `~/.codex/sessions`

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -U pip
python3 -m pip install -r requirements/dev.txt
./scripts/run_model_audit_dashboard.sh
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765).

## CLI Options

```bash
./scripts/run_model_audit_dashboard.sh \
  -p 8765 \
  -h 127.0.0.1 \
  -s ~/.codex/sessions \
  -r ./reports \
  --max-retention-days 31 \
  --max-csv-rows 0
```

## API Endpoints

- `/audit.json`: token integrity checks and reconciliation report
- `/summary.json`: rollups by model/workspace/thread/tool
- `/opportunities.json`: prioritized optimization opportunities
- `/data/catalog.json`: generated dataset metadata

## Development

Run tests:

```bash
python3 -m pytest
```

## Project Structure

- `main.py`: root CLI entrypoint
- `modules/model_audit_mini_app/`: application modules and submodules
- `tests/`: pytest suite
- `scripts/run_model_audit_dashboard.sh`: local launcher
- `requirements/dev.txt`: development dependencies
- `reports/`: dashboard HTML and generated JSON/CSV artifacts
- `docs/screenshots/`: README screenshots
