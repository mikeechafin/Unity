#!/usr/bin/env python3
"""
Version: 2026-03-30 v1.0.0
Changes: New dedicated helper module for all agent_routes exclusive functions (normalization, classification, fingerprinting, credentials). Reduces main routes file size dramatically and improves maintainability.
"""
import hashlib
import re
import os
from maa_libraries import logger

def compute_md5_hash(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def normalize_error_message(error_msg):
    """Normalize error messages by removing host-specific parts."""
    if not error_msg:
        return "Unknown Error"
    return re.sub(r'on host \d+', 'on host', error_msg.lower().strip())

def get_db_credentials():
    """Retrieve database credentials from environment, aligned with collect_agent_data.py."""
    username = 'maamd' # Default, as in collect_agent_data.py
    password = os.environ.get('DB_PASSWORD')
    if not password:
        logger.error("Environment variable DB_PASSWORD is not set")
        raise ValueError("Environment variable DB_PASSWORD is not set")
    return username, password

def classify_error_type(msg: str) -> str:
    """Classify based on your attached logs (CRSeOns, HTTP probes, InventoryException, etc.)."""
    lower = msg.lower()
    if 'crseons' in lower or 'ons' in lower and 'proxy' in lower:
        return 'CRSEONS_SUBSCRIPTION'
    if 'does not service request' in lower or 'http listener' in lower:
        return 'HTTP_PROBE'
    if 'inventoryexception' in lower or 'jaxb' in lower:
        return 'INVENTORY_PARSE'
    if 'heartbeat' in lower or 'upload' in lower and 'timeout' in lower:
        return 'HEARTBEAT_TIMEOUT'
    if 'ora-' in lower:
        return 'ORA_ERROR'
    return 'OTHER'

def compute_fingerprint(msg: str, error_type: str = None) -> str:
    """SHA256 fingerprint for same-root-cause grouping across the fleet."""
    norm = normalize_error_message(msg)
    et = error_type or classify_error_type(msg)
    combined = f"{norm}|{et}"
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()
