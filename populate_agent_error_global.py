#!/usr/bin/env python3
"""Rebuild MAAMD.AGENT_ERROR_GLOBAL from per-host agent_errors (rollup step)."""
import logging
import os
import sys

import config

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(config.OUTPUT_DIR, 'populate_agent_error_global.log')),
    ],
)

from maa_agent_log_parser.global_rollup import populate_agent_error_global


def main():
    try:
        count = populate_agent_error_global()
        print(f'Rollup complete: {count} unique patterns')
    except Exception as exc:
        print(f'Rollup failed: {exc}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()