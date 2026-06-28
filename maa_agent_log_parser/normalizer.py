# Version: 2026-03-29 v1.0.0
# Changes: World-class normalization + fingerprinting engine (tuned on your CRSeOns, InventoryException, HTTP probe, heartbeat samples)
import re
import hashlib
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

NORMALIZATION_PATTERNS = [
    (re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), '[IP]'),
    (re.compile(r'scaqal\d+adm\d+vm\d+\.us\.oracle\.com'), '[HOST]'),
    (re.compile(r'/u01/app/oracle/em/agent_vm\d+/[^ ]+'), '[AGENT_PATH]'),
    (re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'), '[TS]'),
    (re.compile(r'subscriberId=\d+'), '[SUB_ID]'),
    (re.compile(r'TargetGuid=\w+'), '[GUID]'),
    (re.compile(r'(\d+) occurrences'), 'N occurrences'),
    (re.compile(r'\d+'), 'N'),
    (re.compile(r'https?://[^\s]+'), '[URL]'),
]

def normalize_error_message(msg: str) -> str:
    """Normalize for cross-host deduplication and fingerprinting."""
    if not msg:
        return ""
    norm = msg
    for pat, repl in NORMALIZATION_PATTERNS:
        norm = pat.sub(repl, norm)
    return norm.strip()[:4000]

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
