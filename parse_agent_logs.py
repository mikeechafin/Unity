#!/usr/bin/env python3
"""
MAA Agent Log Parser — CLI entry point.

Delegates to the unified maa_agent_log_parser package.
Use --codex for AI-powered new-issue/regression analysis (same pattern as
exa_vm_migration_monitor.py --codex --report).
"""
import argparse
import sys

from maa_agent_log_parser import run_full_pipeline, run_parser


def main():
    parser = argparse.ArgumentParser(description='MAA Unified Agent Log Parser v2.0')
    parser.add_argument('--debug', action='store_true', help='Verbose logging')
    parser.add_argument('--test-host', type=str, default=None, help='Parse single host only')
    parser.add_argument('--parse-only', action='store_true', help='Skip rollup/regression/codex')
    parser.add_argument('--codex', action='store_true', help='Run Codex AI analysis after parse')
    parser.add_argument('--no-codex', action='store_true', help='Skip Codex even if enabled')
    args = parser.parse_args()

    use_codex = None
    if args.codex:
        use_codex = True
    elif args.no_codex:
        use_codex = False

    try:
        if args.parse_only:
            result = run_parser(debug=args.debug, test_host=args.test_host)
        else:
            result = run_full_pipeline(
                debug=args.debug,
                test_host=args.test_host,
                use_codex=use_codex,
            )
        print(f'Parser completed: {result}')
    except Exception as exc:
        print(f'Parser failed: {exc}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()