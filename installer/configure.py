"""
Install-time configuration, called by install_actions.ps1.

1. Creates the data folder layout and seeds missing config/rules
   from the shipped defaults (paths.ensure_data_layout).
2. Applies the HOME_NET / INTERFACES installer properties to
   config\\config.yml.

Values are comma- or semicolon-separated lists, or "auto":

    --home-net "10.0.0.0/8,192.168.1.0/24"
    --interfaces "Ethernet,Wi-Fi"

If both are "auto" (the default) an existing config.yml is left
untouched, so customer edits survive upgrades and repairs.
Otherwise config.yml is rewritten (previous file kept as
config.yml.bak).

Exit codes: 0 = ok, 2 = invalid value.
"""

import argparse
import ipaddress
import re
import shutil
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(APP_DIR))

import paths  # noqa: E402  (creates and seeds the data folder)
import yaml  # noqa: E402


HEADER = """\
# IDSIPS network configuration (written by the installer)
#
# HOME_NET    Networks treated as "home"; auto = subnets of the
#             active adapters.
# INTERFACES  Adapters to capture on (names as in Get-NetAdapter);
#             auto = every adapter that is up.
#
# Restart the IDSIPS service after changing this file.

"""


def parse_list(value):
    """'a, b; c' -> ['a', 'b', 'c'];  '' / 'auto' -> 'auto'."""
    items = [item.strip() for item in re.split(r"[,;]", value or "") if item.strip()]

    if not items or (len(items) == 1 and items[0].lower() == "auto"):
        return "auto"

    return items


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--home-net", default="auto")
    parser.add_argument("--interfaces", default="auto")
    args = parser.parse_args()

    paths.ensure_data_layout()
    print(f"Data folder: {paths.DATA_DIR}")

    home_net = parse_list(args.home_net)
    interfaces = parse_list(args.interfaces)

    if home_net != "auto":
        try:
            home_net = [
                str(ipaddress.ip_network(net, strict=False))
                for net in home_net
            ]
        except ValueError as e:
            print(f"ERROR: invalid HOME_NET value: {e}")
            return 2

    if home_net == "auto" and interfaces == "auto":
        print(f"HOME_NET/INTERFACES = auto; keeping {paths.NIDS_CONFIG_FILE}")
        return 0

    config = {
        "network": {
            "HOME_NET": home_net,
            "INTERFACES": (
                interfaces if interfaces == "auto"
                else [{"name": name} for name in interfaces]
            ),
        }
    }

    config_file = paths.NIDS_CONFIG_FILE

    if config_file.exists():
        shutil.copyfile(config_file, config_file.with_name(config_file.name + ".bak"))

    config_file.write_text(
        HEADER + yaml.safe_dump(config, sort_keys=False),
        encoding="utf-8"
    )

    print(f"Wrote {config_file}: HOME_NET={home_net} INTERFACES={interfaces}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
