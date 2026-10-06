r"""
IDSIPS file locations.

Application files (code, bundled runtime, shipped default rules)
live in APP_DIR. Everything that changes at run time or that a
customer may edit lives in DATA_DIR:

    DATA_DIR
    |-- config\   config.yml (network settings)
    |-- rules\    nids.rules, hids.rules, ips.rules
    |-- logs\     alerts, decisions, service logs (kept on uninstall)
    `-- state\    checkpoints and correlation state

DATA_DIR is chosen as follows:

    1. IDSIPS_DATA environment variable, if set
    2. %ProgramData%\IDSIPS when installed (the installer ships
       the marker file APP_DIR\idsips_installed)
    3. APP_DIR\data when running from a source checkout

Missing config/rules files are seeded from the defaults shipped
in APP_DIR. Existing files are never overwritten, so customer
edits survive upgrades.
"""

import os
import shutil
import sys
from pathlib import Path


APP_DIR = Path(__file__).resolve().parent

INSTALLED_MARKER = APP_DIR / "idsips_installed"


def _resolve_data_dir() -> Path:
    override = os.environ.get("IDSIPS_DATA")

    if override:
        return Path(override)

    if INSTALLED_MARKER.exists():
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        return Path(program_data) / "IDSIPS"

    return APP_DIR / "data"


DATA_DIR = _resolve_data_dir()

CONFIG_DIR = DATA_DIR / "config"
RULES_DIR = DATA_DIR / "rules"
LOG_DIR = DATA_DIR / "logs"
STATE_DIR = DATA_DIR / "state"


# ============================================================
# CONFIG / RULES
# ============================================================

NIDS_CONFIG_FILE = CONFIG_DIR / "config.yml"
HIDS_CONFIG_FILE = CONFIG_DIR / "hids.yaml"

NIDS_RULES_FILE = RULES_DIR / "nids.rules"
HIDS_RULES_FILE = RULES_DIR / "hids.rules"
IPS_RULES_FILE = RULES_DIR / "ips.rules"


# ============================================================
# LOGS (outputs, kept for investigation)
# ============================================================

HIDS_EVENTS_FILE = LOG_DIR / "event.json"
NIDS_ALERTS_FILE = LOG_DIR / "alerts.json"
CORRELATION_FILE = LOG_DIR / "correlation.json"
IPS_ALERTS_FILE = LOG_DIR / "ips_alerts.json"
IPS_PASS_FILE = LOG_DIR / "ips_pass.json"
IPS_INLINE_BLOCKS_FILE = LOG_DIR / "ips_inline_blocks.json"
WORKER_LOG_DIR = LOG_DIR / "workers"


# ============================================================
# STATE (checkpoints)
# ============================================================

HIDS_COLLECTOR_CHECKPOINT_FILE = STATE_DIR / "hids_checkpoints.json"
ALERT_MANAGER_HIDS_CHECKPOINT_FILE = STATE_DIR / "alert_manager_hids_checkpoint.json"
ALERT_MANAGER_NIDS_CHECKPOINT_FILE = STATE_DIR / "alert_manager_nids_checkpoint.json"
CORRELATION_STATE_FILE = STATE_DIR / "correlation_state.json"
IPS_WORKER_CHECKPOINT_FILE = STATE_DIR / "ips_worker_checkpoint.json"


# ============================================================
# DEFAULTS SHIPPED WITH THE APPLICATION
# ============================================================

DEFAULT_FILES = {
    NIDS_CONFIG_FILE: APP_DIR / "NIDS" / "config.yml",
    NIDS_RULES_FILE: APP_DIR / "NIDS" / "rules" / "nids.rules",
    HIDS_RULES_FILE: APP_DIR / "hids" / "hids.rules",
    IPS_RULES_FILE: APP_DIR / "IPS" / "ips.rules",
}


def ensure_data_layout() -> None:
    """
    Create the data folders and seed missing config/rules files
    from the shipped defaults. Never overwrites existing files.
    Never raises: a failure is reported on stderr and the
    component that needs the file reports its own error.
    """

    for directory in (CONFIG_DIR, RULES_DIR, LOG_DIR, STATE_DIR, WORKER_LOG_DIR):
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            print(f"[IDSIPS] Cannot create {directory}: {e}", file=sys.stderr)

    for target, default in DEFAULT_FILES.items():
        if target.exists() or not default.exists():
            continue

        try:
            shutil.copyfile(default, target)
        except OSError as e:
            print(f"[IDSIPS] Cannot seed {target} from {default}: {e}", file=sys.stderr)


ensure_data_layout()
