# Unity (MAA Unified Application)

Oracle Maximum Availability Architecture (MAA) operations platform for Exadata fleet management — environment setup, coordinated patching, EM agent lifecycle, ASR fault testing, and real-time monitoring.

## Quick Start

```bash
# 1. Install dependencies
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium   # required for ASR fault testing

# 2. Set required environment variables
export DB_PASSWORD='<maamd-db-password>'
export FLASK_SECRET_KEY='<random-secret>'

# Optional overrides (defaults work for local dev)
export MAA_APP_ROOT="$(pwd)"          # application root directory
export MAA_OUTPUT_DIR="$(pwd)/output" # runtime logs
export SSH_KEY_PATH="$HOME/.ssh/id_ed25519_maa"
export MAA_PRODUCTION=1               # enforces FLASK_SECRET_KEY in production

# 3. Create local secrets (not in git)
# Fernet key for credential vault — generate once:
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" > encryption_key.txt
chmod 600 encryption_key.txt

# TLS cert for HTTPS (or place your own server.crt / server.key)
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"

# 4. Run
python3 maa_unified_app.py --host 0.0.0.0 --port 6003
```

Default URL: `https://<host>:6003`

## Prerequisites

| Component | Purpose |
|-----------|---------|
| Oracle DB (`MAAMD` schema) | Topology, credentials, jobs, audit log |
| Redis (`localhost:6379`) | Celery broker for ASR fault tasks |
| SSH key (`id_ed25519_maa`) | Fleet automation |
| `patchmgr` bundles | Coordinated Exadata patching |

See `MAA_Unified_Developers_Guide.md` for full architecture, schema, and extension guide.

## Project Structure

```
maa_unified_app.py          # Main Flask + SocketIO entry point
*_routes.py                 # Feature blueprints (setup, agent, fault, rti, …)
maa_libraries.py            # SSH, credentials, reachability utilities
maa_scheduler.py            # APScheduler + Oracle jobstore
environment_setup_registry.py  # Plugin discovery for setup actions
scripts/plugins/            # Python setup plugins
scripts/scl/                # CellCLI scripts
scripts/ilom/               # ILOM scripts
templates/                  # Jinja2 UI
output/                     # Runtime logs (gitignored)
```

## Security Notes

The following are **excluded from git** and must be provisioned per environment:

- `encryption_key.txt` — Fernet key for `ACCESS_CREDENTIALS` decryption
- `server.crt` / `server.key` — TLS certificates
- `output/` — execution logs (may contain hostnames and operational detail)

## Modules

| Route prefix | Feature |
|--------------|---------|
| `/` | Operations dashboard |
| `/setup` | Environment setup & patching |
| `/agent` | EM agent lifecycle |
| `/fault` | ASR fault injection & validation |
| `/rti` | Real-time insight streaming |
| `/migration` | Live migration test results |
| `/jobs` | Scheduled fleet jobs |
| `/access` | Credential vault |
| `/oedacli` | OEDA CLI integration |
| `/fleet-health` | SSH & ILOM failure trends dashboard |
| `/agent/parser_status` | Agent log parser status + run pipeline |
| `/agent/error_summary` | Fingerprint-grouped OEM agent errors |
| `/agent/ai_insights` | Codex AI analysis — new issues & regressions |

### Agent Log Parser

Unified pipeline in `maa_agent_log_parser/`:

```bash
# Full pipeline: crawl → normalize/classify → rollup → regression → Codex
python3 parse_agent_logs.py --debug --codex

# Parse only (no rollup/AI)
python3 parse_agent_logs.py --parse-only --test-host myhost.example.com
```

Set `CODEX_CLI=codex` (OpenAI Codex CLI) or `OPENAI_API_KEY` for AI analysis.
Regression detection compares fingerprint snapshots between runs (`output/agent_error_analysis/`).

## Configuration (`config.py`)

Central configuration reads from environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `MAA_APP_ROOT` | repo directory | Application root |
| `DB_PASSWORD` | *(required)* | Oracle `maamd` password |
| `DB_DSN` | devel TNS | Oracle connection string |
| `FLASK_SECRET_KEY` | dev fallback | Session signing (required when `MAA_PRODUCTION=1`) |
| `MAA_PRODUCTION` | off | Fail fast if secret key missing |
| `MAA_OUTPUT_DIR` | `$APP_ROOT/output` | Log files for jobs and Fleet Health |
| `SSH_KEY_PATH` | `~/.ssh/id_ed25519_maa` | Fleet SSH automation key |
| `CELERY_BROKER` | `redis://localhost:6379/0` | Celery broker URL |
| `RTI_BASE_DIR` | `$OUTPUT_DIR/RTI` | RTI capture storage |
| `EMCLI_PATH` | `$APP_ROOT/EMCLI/emcli` | Enterprise Manager CLI |
| `ENCRYPTION_KEY_FILE` | `$APP_ROOT/encryption_key.txt` | Credential vault Fernet key |