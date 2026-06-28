#!/usr/bin/env python3
"""
Version: 2026-06-28 v2.0.0
Agent route helpers — delegates normalization/classification to maa_agent_log_parser.
"""
import os

from maa_libraries import logger
from maa_agent_log_parser.normalizer import (
    normalize_error_message,
    classify_error_type,
    compute_fingerprint,
)


def compute_md5_hash(text):
    """Legacy helper — prefer compute_fingerprint for new code."""
    import hashlib
    return hashlib.md5(text.encode('utf-8')).hexdigest()


def get_db_credentials():
    username = 'maamd'
    password = os.environ.get('DB_PASSWORD')
    if not password:
        logger.error('Environment variable DB_PASSWORD is not set')
        raise ValueError('Environment variable DB_PASSWORD is not set')
    return username, password