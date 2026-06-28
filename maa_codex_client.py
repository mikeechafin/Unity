#!/usr/bin/env python3
"""
Shared Codex / OpenAI client for AI-powered fleet analysis.

Mirrors the pattern used by exa_vm_migration_monitor.py --codex --report:
invoke the Codex CLI when available, fall back to OpenAI API.
"""
import json
import logging
import os
import shutil
import subprocess

import config

logger = logging.getLogger(__name__)


def _try_codex_cli(prompt: str) -> dict:
    cli = config.CODEX_CLI
    if not cli or not shutil.which(cli):
        return None

    invocations = [
        [cli, 'exec', '--full-auto', prompt],
        [cli, 'exec', prompt],
        [cli, prompt],
    ]
    for cmd in invocations:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.CODEX_TIMEOUT,
                env={**os.environ, 'OPENAI_API_KEY': os.environ.get('OPENAI_API_KEY', '')},
            )
            if result.returncode == 0 and result.stdout.strip():
                return {
                    'source': 'codex_cli',
                    'text': result.stdout.strip(),
                    'model': config.CODEX_MODEL,
                }
            if result.stderr:
                logger.debug('Codex CLI stderr (%s): %s', cmd, result.stderr[:300])
        except subprocess.TimeoutExpired:
            logger.warning('Codex CLI timed out after %ss', config.CODEX_TIMEOUT)
        except Exception as exc:
            logger.debug('Codex CLI invocation failed (%s): %s', cmd, exc)
    return None


def _try_openai_api(prompt: str) -> dict:
    api_key = config.OPENAI_API_KEY or os.environ.get('OPENAI_API_KEY')
    if not api_key:
        return None
    try:
        import urllib.request
        payload = json.dumps({
            'model': config.CODEX_MODEL,
            'messages': [
                {'role': 'system', 'content': 'You are an Oracle Enterprise Manager fleet operations analyst.'},
                {'role': 'user', 'content': prompt},
            ],
            'temperature': 0.2,
        }).encode('utf-8')
        req = urllib.request.Request(
            'https://api.openai.com/v1/chat/completions',
            data=payload,
            headers={
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json',
            },
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=config.CODEX_TIMEOUT) as resp:
            body = json.loads(resp.read().decode('utf-8'))
        text = body['choices'][0]['message']['content']
        return {'source': 'openai_api', 'text': text, 'model': config.CODEX_MODEL}
    except Exception as exc:
        logger.warning('OpenAI API call failed: %s', exc)
        return None


def run_codex_prompt(prompt: str) -> dict:
    """
    Run an AI analysis prompt. Returns dict with keys: text, source, model.
    Raises RuntimeError if no backend is available.
    """
    if not config.CODEX_ENABLED:
        raise RuntimeError('Codex analysis disabled (set CODEX_ENABLED=1 to enable)')

    result = _try_codex_cli(prompt)
    if result:
        return result

    result = _try_openai_api(prompt)
    if result:
        return result

    raise RuntimeError(
        'No Codex backend available. Install the codex CLI or set OPENAI_API_KEY.'
    )


def is_codex_available() -> bool:
    if not config.CODEX_ENABLED:
        return False
    return bool(shutil.which(config.CODEX_CLI) or config.OPENAI_API_KEY or os.environ.get('OPENAI_API_KEY'))