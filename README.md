# AI Incident Copilot

Production-oriented incident copilot with a chat-first UX, LangGraph workflow orchestration, approval-gated ServiceNow writes, vector retrieval, and runtime traces.

## Stack
- Backend: FastAPI + LangGraph + Azure OpenAI
- Retrieval: Chroma vector store (`vector`, optional `manifest_vector` prefilter)
- Frontend: React (Vite build served by FastAPI)
- Persistence: SQLite (`.state/chat.db`), checkpoint files (`.state/checkpoints`), traces (`traces/`)

## Prerequisites
- Python 3.12+
- Node.js 18+

## Setup
1. Copy env file and configure values:

```bash
cp .env.example .env
```

2. Install Python dependencies:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Optional dev tooling:

```bash
.venv/bin/pip install -r requirements-dev.txt
```

3. Install frontend dependencies and build:

```bash
npm install --prefix frontend
npm run build --prefix frontend
```

4. Start the API server:

```bash
.venv/bin/uvicorn apps.main:app --host 0.0.0.0 --port 8000
```

5. Open:

```text
http://127.0.0.1:8000
```

## Core Environment Variables
- `SERVICENOW_INSTANCE`
- `SERVICENOW_AUTH_MODE` (`basic`, `url`, `oauth`)
- For `basic`/`url`: `SERVICENOW_USERNAME`, `SERVICENOW_PASSWORD`
- For `oauth`: `SERVICENOW_BEARER_TOKEN` or OAuth client/user variables
- `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_DEPLOYMENT`, `AZURE_OPENAI_API_VERSION`
- `RETRIEVAL_MODE` (`vector` or `manifest_vector`)

## API Endpoints
- `GET /health`
- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/chat/sessions`
- `GET /api/chat/sessions/{chat_id}`
- `POST /api/chat`
- `POST /api/run-copilot`
- `POST /api/run-copilot/start`
- `POST /api/run-copilot/resume`

## Production Notes
- ServiceNow writes are blocked until approval is explicitly `approved`.
- Idempotency keys are used for create/update safety.
- Request logs include request id and per-request latency.
- Token/cost tracking is currently estimated in trace summaries.

## Quality Checks

```bash
.venv/bin/ruff check apps src tests
.venv/bin/mypy apps tests
.venv/bin/python -m pytest
```
