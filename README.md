# SentinelAI

SentinelAI is a local cybersecurity detection prototype for **synthetic events and synthetic network-flow data**. It combines deterministic event rules with a Random Forest classifier, an Isolation Forest anomaly detector, simulated specialist agents, a SQLite-backed event/alert store, and a React dashboard.

> **Scope and limitations:** the supplied files are generated synthetic records inspired by commonly used UNSW-NB15 feature names. They are not official UNSW-NB15 data, verified telemetry, or evidence of real-world protection. Simulated agents run in the backend process. SentinelAI does not connect to real endpoints, inspect files, execute processes, collect credentials, or perform automatic response actions.

## Requirements

- Windows 10/11
- Python 3.10 or later (Python 3.11 recommended)
- Node.js 20 or later and npm
- VS Code (optional)

No API keys, paid services, GPU, external model service, or PowerShell execution-policy changes are needed.

## Project layout

```text
backend/
  app/                 FastAPI API, SQLAlchemy models, schemas, detection and agent services
  artifacts/           Locally trained model and evaluation report
  data/raw/            Supplied synthetic CSV snapshots and provenance metadata
  data/processed/      Preprocessed synthetic dataset
  scripts/             Preprocessing, training, and evaluation commands
  tests/               Backend API, model, and preprocessing tests
frontend/
  src/                 React pages, dashboard components, API client, and styles
```

SQLite is initialized automatically on the first backend startup at `backend\sentinelai.db`. Initialization creates missing tables and does not reset existing data.

## Dataset

The supplied snapshots are copied unchanged into `backend\data\raw\`:

- `sentinelai_synthetic_cleaned.csv` — 12,000 synthetic network-flow-style records.
- `sentinelai_agent_events.csv` — synthetic agent-event examples.

Their provenance and limitations are recorded in `backend\data\PROVENANCE.json`. To use another compatible CSV, pass its path to the preprocessing or training script. The `label` convention is `0 = synthetic normal` and `1 = synthetic threat-like`. `label`, `attack_cat`, event identifiers, timestamps, endpoint IDs, agent type, source, and scenario metadata are excluded from model features.

The `unseen_pattern_simulation` / `Novel_Anomaly` records are held out of model training and validation. Their reported recall measures performance only on that held-out synthetic category; because those rows contain no normal examples, they do not provide a false-positive estimate for that category and do not establish zero-day detection.

## Setup and run

### 1. Create a backend virtual environment and install dependencies

In PowerShell:

```powershell
cd D:\sentinelAI\backend
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 2. Preprocess and train the models

```powershell
.\.venv\Scripts\python.exe -m scripts.preprocess
.\.venv\Scripts\python.exe -m scripts.train
```

The training command creates `backend\artifacts\detection_model.joblib` and `backend\artifacts\training_metrics.json`. The classifier uses a stratified train/validation/test split of known patterns; its probability threshold is selected on validation data. The Isolation Forest is fit only on normal training rows and receives a separately tuned validation threshold. Evaluation reports the held-out test results, false-positive rate, latency, and known attack-category metrics.

Convenience commands are also available:

```powershell
.\.venv\Scripts\python.exe -m scripts.train_classifier
.\.venv\Scripts\python.exe -m scripts.train_anomaly_model
.\.venv\Scripts\python.exe -m scripts.evaluate_models
```

The two named training entry points use the shared training workflow, which refreshes both model artifacts to keep the thresholds and preprocessing pipeline consistent. If model files are absent or invalid, the API still starts and deterministic rules remain available; the dashboard reports the models as unavailable.

### 3. Start the backend

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Check `http://127.0.0.1:8000/api/health`. Interactive API documentation is at `http://127.0.0.1:8000/docs`.

### 4. Start the frontend

Open a second PowerShell terminal:

```powershell
cd D:\sentinelAI\frontend
Copy-Item .env.example .env
npm install
npm run dev
```

Open `http://127.0.0.1:5173`. The configured API base URL is `VITE_API_BASE_URL` in `frontend\.env`; it defaults to `http://127.0.0.1:8000/api`. The backend accepts the local Vite origins `http://localhost:5173` and `http://127.0.0.1:5173`; override them with `SENTINELAI_CORS_ORIGINS` if needed.

## API overview

All application endpoints use the `/api` prefix:

- `GET /health`, `GET /dashboard/stats`
- `GET /agents`, `POST /agents/register`, `GET /agents/{agent_id}`
- `GET /endpoints`, `GET /endpoints/{endpoint_id}`
- `GET /events`, `POST /events`, `GET /events/{event_id}`, `POST /detect`
- `GET /alerts`, `GET /alerts/{alert_id}`, `PATCH /alerts/{alert_id}`
- `POST /simulations/run`, `GET /simulations/history`, `GET /simulations/{simulation_id}`
- `GET /analytics/summary`, `GET /analytics/confusion-matrix`, `GET /analytics/attack-categories`
- `GET /models/status`, `GET /evaluations`, `POST /feedback`
- `GET /settings`, `PATCH /settings`

List APIs accept `limit` and `offset`; event and alert lists also provide filters. Event inputs are validated with Pydantic. Model inference is restricted to compatible network-flow events with all required features; authentication, file, API, and system events use their supported rules instead.

## Safe simulations

The Simulation Center submits generated records through the same persistence and detection pipeline as event ingestion. Available scenarios include normal login/network behavior, brute-force-like login activity, DoS-like traffic spikes, suspicious API request bursts, file-modification bursts, unusual system activity, and a novel behavioral combination. Each run stores its predeclared expected outcome, actual outcome, generated event/alert IDs, processing duration, detection methods, and evaluation result. A normal simulation that creates an alert is reported as a false positive, not suppressed.

No simulation reads or changes real files, launches or terminates processes, or sends network traffic to external systems.

## Tests and production build

From `backend`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

From `frontend`:

```powershell
npm run build
```

Tests cover API health, database initialization, event validation and ingestion, model-unavailable behavior, agent registration, normal and suspicious event processing, all simulation families, held-out novel-pattern execution, alert updates, feedback, analytics, preprocessing, and threshold selection.

## Troubleshooting

- **API unavailable in the dashboard:** start the backend on port `8000`; confirm `GET http://127.0.0.1:8000/api/health` works and `VITE_API_BASE_URL` points to the correct `/api` base URL.
- **CORS error:** set `SENTINELAI_CORS_ORIGINS` to a comma-separated list of the exact local frontend origins and restart the backend.
- **Models show unavailable:** run `python -m scripts.train` from `backend`; rule-based detection remains available while model files are missing.
- **Missing Python packages:** install `backend\requirements.txt` using the virtual environment's Python executable.
- **SQLite locked or stale data:** stop duplicate backend processes using the database before retrying. Do not delete the database to troubleshoot; it contains local application state.
- **Different dataset:** place the compatible synthetic CSV in `backend\data\raw\` or pass its path using the `--input` argument documented by the script's `--help` output.

## Evaluation cautions

Reported precision, recall, F1, confusion matrices, false-positive rates, and latency are calculated from the supplied synthetic evaluation splits. They are useful for validating this prototype's code paths and synthetic scenarios only. Synthetic performance cannot predict performance on real organizations, endpoints, or future threats.
