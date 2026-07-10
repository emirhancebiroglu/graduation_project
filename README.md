# StratosAI IDS Demo Platform

<p align="center">
  <img src="https://img.shields.io/badge/Snort%203-IDS%20Engine-111827?style=for-the-badge&logo=hackthebox&logoColor=white" alt="Snort 3" />
  <img src="https://img.shields.io/badge/FastAPI-Backend-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Next.js-Frontend-000000?style=for-the-badge&logo=nextdotjs&logoColor=white" alt="Next.js" />
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Detection%20Modes-Flow%20%7C%20Window-0F172A?style=flat-square" alt="Detection Modes" />
  <img src="https://img.shields.io/badge/Explainability-SHAP-6E56CF?style=flat-square" alt="SHAP" />
  <img src="https://img.shields.io/badge/Realtime-WebSocket-0EA5E9?style=flat-square" alt="WebSocket" />
  <img src="https://img.shields.io/badge/Status-Demo%20Platform-22C55E?style=flat-square" alt="Demo Platform" />
</p>

StratosAI is a full-stack intrusion detection demo built for network security research and graduation-project evaluation. It combines Snort 3, custom C++ inspectors, XGBoost and LSTM-based detection pipelines, SHAP-based explainability, and a Next.js dashboard with a FastAPI backend for replaying PCAPs and visualizing results in real time.

The project is designed to compare multiple detection strategies across common attack families:

- DoS
- DDoS
- Port scan
- Brute force
- Bot client activity

It is best understood as an interactive research lab and presentation platform rather than a production IDS deployment.

## At a Glance

| Area | What It Does |
| --- | --- |
| Detection | Replays PCAPs through Snort 3 with custom inspectors and ML models |
| Explainability | Adds SHAP-backed alert explanations and feature narratives |
| Evaluation | Compares detectors using frozen baselines and confusion matrices |
| UI | Provides a live dashboard with scenario selection and streamed alerts |
| Automation | Includes replay, training, analysis, and benchmarking scripts |

## Why This Project Stands Out

- Real-time replay of PCAP captures through Snort 3
- Custom Snort inspectors for per-flow and window-level detection
- Machine learning models for attack detection and false-positive reduction
- SHAP explanations for alert-level interpretability
- Scenario-based evaluation with frozen baselines and confusion matrices
- Live dashboard with WebSocket-driven updates
- English and Turkish UI support in the demo application

## Architecture

The repository is organized around four main layers:

- `plugins/` contains Snort 3 inspectors implemented in C++
- `configs/` contains Snort Lua configurations and rule files
- `demo-app/api/` contains the FastAPI replay and evaluation backend
- `demo-app/web/` contains the Next.js dashboard

Supporting assets and workflows live under:

- `train/` for model training and tuning
- `evaluate/` for offline evaluation
- `scripts/` for experimentation, replay, SHAP, and diagnostics
- `docker/snort-sim/` for containerized Snort simulation
- `data_prep/` for dataset preparation utilities

## Repository Layout

```text
configs/              Snort Lua configs and rule sets
data_prep/            Dataset preparation scripts
demo-app/api/         FastAPI backend, replay control, SHAP explainers
demo-app/web/         Next.js dashboard
docker/snort-sim/     Docker-based Snort simulation environment
evaluate/             Evaluation helpers
plugins/              Custom Snort 3 inspectors and shared sources
scripts/              Analysis, replay, benchmarking, and test scripts
train/                Model training and threshold optimization
```

## Tech Stack

| Layer | Technologies |
| --- | --- |
| IDS / Runtime | Snort 3, Lua, C++, XGBoost runtime |
| Backend | Python 3.11+, FastAPI, Uvicorn, WebSockets, Pydantic |
| Frontend | Next.js 16, React 19, TypeScript, Tailwind CSS 4 |
| Explainability | SHAP, IsolationForest scoring helpers |
| Dev / Build | CMake, Docker, pnpm, shell scripts |

## Requirements

The project was built for a Linux-oriented IDS workflow. To run the full stack locally you will typically need:

- Python 3.11 or newer
- Node.js 20 or newer
- `pnpm` for the frontend
- Snort 3 with the required DAQ/runtime dependencies
- A C++ toolchain and CMake for building the plugins
- XGBoost runtime libraries and headers for the native inspectors
- Access to the PCAPs, trained models, and generated outputs used by the scenarios

## Quick Start

### 1. Clone or open the repository

Work from the repository root and keep the folder structure intact.

### 2. Review local path assumptions

Several scripts and configuration files use absolute paths from the original workstation, such as `/home/emirhan/bitirme/...`.

If your checkout lives elsewhere, update those paths before running the simulation, plugin build, or replay scripts.

### 3. Prepare the backend environment

```bash
cd demo-app/api
python -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Then start the API:

```bash
.venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8000 --app-dir .
```

The backend exposes the replay API, WebSocket stream, health checks, and SHAP explanation endpoints.

### 4. Prepare the frontend

```bash
cd ../web
pnpm install
pnpm dev
```

By default the app runs on `http://localhost:3000` and connects to the API at `http://localhost:8000`.

If the API is hosted elsewhere, set:

```bash
NEXT_PUBLIC_API_URL=http://your-api-host:8000
```

## Demo Application

The dashboard in `demo-app/web/` provides:

- Scenario selection
- Replay start and stop controls
- Live alert feed
- Detection coverage and impact panels
- Evaluation summaries
- SHAP-powered explainability views
- Language switching

The backend in `demo-app/api/` provides:

- `/api/health`
- `/api/config`
- `/api/config/scenarios`
- `/api/replay/start`
- `/api/replay/stop`
- `/api/history`
- `/api/explain/{alert_id}`
- `/ws`

## Scenarios

The demo is scenario-driven. Scenario definitions live in:

- `demo-app/api/scenarios.py`
- `demo-app/api/scenario_baselines.json`

Each scenario maps to:

- A PCAP slice
- A primary detection engine
- Scenario-specific metrics
- Frozen baselines for ML and community rules

The currently supported scenario keys are:

- `dos`
- `ddos`
- `portscan`
- `bruteforce`
- `bot`

## Snort Simulation

The repository also includes a Docker-based Snort simulation under `docker/snort-sim/`.

This environment is intended for replaying traffic, validating alerts, and generating outputs used by the demo application and evaluation scripts.

Typical components include:

- a target container
- an attacker container
- a Snort container attached to the same bridge network

The container setup mounts local plugins, models, configs, and PCAPs into the Snort environment.

## Native Plugins

Custom inspectors live in `plugins/` and are built separately per detector. They include implementations for:

- DoS detection
- DDoS aggregation
- Port scan detection
- Brute-force detection
- Bot client detection
- ML-assisted inspection

Each plugin folder usually contains:

- `src/` for the implementation
- `CMakeLists.txt` for the build
- `build.sh` for local compilation

## Training and Evaluation

The `train/`, `evaluate/`, and `scripts/` directories contain the research workflow used to build and validate the models.

They cover:

- feature extraction
- dataset labeling
- threshold search
- model training and fine-tuning
- SHAP analysis
- confusion matrix generation
- false-positive diagnostics
- cross-day and cross-dataset evaluation

## Data and Artifacts

Generated or environment-specific assets are intentionally kept outside version control where possible:

- raw and processed datasets
- trained models
- replay outputs
- logs
- results

See `.gitignore` for the current exclusions.

## Operational Notes

- The backend preloads ground-truth data on startup so the first replay is not blocked by CSV parsing.
- The UI communicates with the backend over REST and WebSocket channels.
- Scenario metrics are frozen and should be treated as reference baselines, not live recalculations from the frontend.
- Some alert enrichment happens after replay completion, so the UI may receive late updates while the backend finalizes evaluation.

## Troubleshooting

- If the dashboard cannot connect, verify that the API is running on `http://localhost:8000`.
- If replay start fails, confirm that the referenced PCAP exists in the expected `pcaps/` location.
- If plugin builds fail, check Snort 3, XGBoost, and CMake dependencies first.
- If metrics look incorrect, review the absolute paths used in the scripts and configs, especially when running outside the original workstation layout.

## License

No license file is included in this repository snapshot. Add one if you plan to publish or redistribute the project.
