#!/usr/bin/env python3
"""Central configuration for MAA Unified Application."""
import os

# Application root — override with MAA_APP_ROOT env var
APP_ROOT = os.environ.get('MAA_APP_ROOT', os.path.dirname(os.path.abspath(__file__)))

# Database
DB_USER = os.environ.get('DB_USER', 'maamd')
DB_DSN = os.environ.get(
    'DB_DSN',
    '(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=scaqaa04cel12vm02.us.oracle.com)(PORT=1521))'
    '(CONNECT_DATA=(SERVICE_NAME=maapdb_devel.us.oracle.com)))'
)
DB_PASSWORD = os.environ.get('DB_PASSWORD')

# Security
FLASK_SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')
MAA_PRODUCTION = os.environ.get('MAA_PRODUCTION', '').lower() in ('1', 'true', 'yes')

# SSH keys
SSH_KEY_PATH = os.environ.get('SSH_KEY_PATH', '/home/maatest/.ssh/id_ed25519_maa')
SSH_KEY_PUB_PATH = SSH_KEY_PATH + '.pub'
SSH_LEGACY_KEY_PATH = os.environ.get('SSH_LEGACY_KEY_PATH', SSH_KEY_PATH)

# Paths
OUTPUT_DIR = os.environ.get('MAA_OUTPUT_DIR', os.path.join(APP_ROOT, 'output'))
SCRIPTS_DIR = os.path.join(APP_ROOT, 'scripts')
SCL_DIR = os.path.join(SCRIPTS_DIR, 'scl')
ILOM_DIR = os.path.join(SCRIPTS_DIR, 'ilom')
SHELL_DIR = os.path.join(SCRIPTS_DIR, 'shell')
PLUGIN_DIR = os.path.join(SCRIPTS_DIR, 'plugins')

# Logs
SSH_SETUP_LOG = os.path.join(OUTPUT_DIR, 'setup_passwordless_ssh.log')
ILOM_COLLECT_LOG = os.path.join(OUTPUT_DIR, 'collect_ilom_data.log')
INDEX_STATS_LOG = os.path.join(OUTPUT_DIR, 'update_index_stats.log')
AGENT_MAINTAIN_LOG = os.path.join(OUTPUT_DIR, 'maintain_em_agents.log')

# Runtime
LOCK_FILE = os.environ.get('MAA_LOCK_FILE', '/tmp/maa_unified_app_new.lock')
PID_FILE = os.environ.get('MAA_PID_FILE', '/tmp/maa_unified_app_new.pid')
ENCRYPTION_KEY_FILE = os.environ.get('ENCRYPTION_KEY_FILE', os.path.join(APP_ROOT, 'encryption_key.txt'))
TLS_CERT = os.environ.get('TLS_CERT', os.path.join(APP_ROOT, 'server.crt'))
TLS_KEY = os.environ.get('TLS_KEY', os.path.join(APP_ROOT, 'server.key'))

# Celery / Redis
CELERY_BROKER = os.environ.get('CELERY_BROKER', 'redis://localhost:6379/0')

# Migration reports
MIGRATION_REPORTS_DIR = os.environ.get(
    'MIGRATION_REPORTS_DIR',
    os.path.expanduser('~/mchafin/lm_test/migration_tests')
)

# RTI
RTI_BASE_DIR = os.environ.get('RTI_BASE_DIR', os.path.join(OUTPUT_DIR, 'RTI'))

# External tooling (provisioned per environment, not in git)
EMCLI_PATH = os.environ.get('EMCLI_PATH', os.path.join(APP_ROOT, 'EMCLI', 'emcli'))
OEDA_BASE_DIR = os.environ.get('OEDA_BASE_DIR', os.path.join(APP_ROOT, 'OEDA'))

# Agent log parser
AGENT_PARSER_LOG = os.path.join(OUTPUT_DIR, 'parse_agent_logs.log')
AGENT_ERROR_ANALYSIS_DIR = os.path.join(OUTPUT_DIR, 'agent_error_analysis')
AGENT_ERROR_SNAPSHOT_FILE = os.path.join(AGENT_ERROR_ANALYSIS_DIR, 'current_snapshot.json')
AGENT_ERROR_PREVIOUS_SNAPSHOT = os.path.join(AGENT_ERROR_ANALYSIS_DIR, 'previous_snapshot.json')
AGENT_ERROR_CHANGES_FILE = os.path.join(AGENT_ERROR_ANALYSIS_DIR, 'changes.json')
AGENT_ERROR_ANALYSIS_FILE = os.path.join(AGENT_ERROR_ANALYSIS_DIR, 'latest_analysis.json')

# Codex / OpenAI (same pattern as exa_vm_migration_monitor --codex)
CODEX_CLI = os.environ.get('CODEX_CLI', 'codex')
CODEX_ENABLED = os.environ.get('CODEX_ENABLED', '1').lower() in ('1', 'true', 'yes')
CODEX_MODEL = os.environ.get('CODEX_MODEL', 'gpt-4o')
CODEX_TIMEOUT = int(os.environ.get('CODEX_TIMEOUT', '120'))
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
REGRESSION_SPIKE_PCT = float(os.environ.get('REGRESSION_SPIKE_PCT', '50'))
REGRESSION_MIN_DELTA = int(os.environ.get('REGRESSION_MIN_DELTA', '10'))


def require_secret_key():
    """Fail fast in production if FLASK_SECRET_KEY is not set."""
    if MAA_PRODUCTION and not FLASK_SECRET_KEY:
        raise RuntimeError(
            'FLASK_SECRET_KEY must be set when MAA_PRODUCTION=1. '
            'Refusing to start with the insecure default.'
        )
    return FLASK_SECRET_KEY or 'temporary-secure-key-dev-only'