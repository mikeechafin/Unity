# Version: 2026-06-28 v2.0.0
# Normalization + rule-based classification + SHA256 fingerprinting for fleet dedup.
import hashlib
import logging
import re

logger = logging.getLogger(__name__)

NORMALIZATION_PATTERNS = [
    (re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), '[IP]'),
    (re.compile(r'scaq[a-z]+\d+adm\d+vm\d+\.us\.oracle\.com', re.I), '[HOST]'),
    (re.compile(r'/u01/app/oracle/em/agent_vm\d+/[^ ]+'), '[AGENT_PATH]'),
    (re.compile(r'\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}'), '[TS]'),
    (re.compile(r'subscriberId=\d+', re.I), '[SUB_ID]'),
    (re.compile(r'TargetGuid=\w+', re.I), '[GUID]'),
    (re.compile(r'(\d+) occurrences', re.I), 'N occurrences'),
    (re.compile(r'https?://[^\s]+'), '[URL]'),
    (re.compile(r'\b\d{4,5}\b'), '[PORT]'),
    (re.compile(r'\b\d+%\b'), '[PCT]'),
    (re.compile(r'\[\d+\]'), '[N]'),
    (re.compile(r'\d+'), 'N'),
]

ERROR_LINE_PATTERNS = [
    re.compile(r'(?:ERROR|SEVERE|CRITICAL|FATAL)[:\s]+(.+)', re.I),
    re.compile(r'(?:WARNING|WARN)[:\s]+(.+)', re.I),
    re.compile(r'Exception[:\s]+(.+)', re.I),
    re.compile(r'Failed[:\s]+(.+)', re.I),
    re.compile(r'(ORA-\d+:\s*.+)', re.I),
    re.compile(r'(CRSeOns.+)', re.I),
    re.compile(r'(Upload failed.+)', re.I),
]

EXCLUDE_PATTERNS = [
    re.compile(r'^INFO:', re.I),
    re.compile(r'^DEBUG:', re.I),
    re.compile(r'Successfully', re.I),
]


def normalize_error_message(msg: str) -> str:
    if not msg:
        return ''
    norm = msg.strip()
    for pat, repl in NORMALIZATION_PATTERNS:
        norm = pat.sub(repl, norm)
    return norm.strip()[:4000]


def classify_error_type(msg: str) -> str:
    lower = msg.lower()
    if 'crseons' in lower or ('ons' in lower and 'proxy' in lower):
        return 'CRSEONS_SUBSCRIPTION'
    if 'does not service request' in lower or 'http listener' in lower:
        return 'HTTP_PROBE'
    if 'inventoryexception' in lower or 'jaxb' in lower:
        return 'INVENTORY_PARSE'
    if 'heartbeat' in lower or ('upload' in lower and 'timeout' in lower):
        return 'HEARTBEAT_TIMEOUT'
    if 'authentication failed' in lower or 'permission denied' in lower:
        return 'AUTH_FAILURE'
    if 'connection refused' in lower or 'connection timed out' in lower or 'unreachable' in lower:
        return 'CONNECTIVITY'
    if 'out of memory' in lower or 'disk full' in lower or 'no space' in lower:
        return 'RESOURCE'
    if 'plugin' in lower and 'fail' in lower:
        return 'PLUGIN_FAILURE'
    if 'ora-' in lower:
        return 'ORA_ERROR'
    return 'OTHER'


def compute_fingerprint(msg: str, error_type: str = None) -> str:
    norm = normalize_error_message(msg)
    et = error_type or classify_error_type(msg)
    combined = f'{norm}|{et}'
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()


def extract_error_from_line(line: str):
    """Return (raw_message, error_type, fingerprint, normalized) or None."""
    line = line.strip()
    if not line or len(line) < 10:
        return None
    for ex in EXCLUDE_PATTERNS:
        if ex.search(line):
            return None
    raw = None
    for pat in ERROR_LINE_PATTERNS:
        m = pat.search(line)
        if m:
            raw = m.group(1).strip() if m.lastindex else m.group(0).strip()
            break
    if not raw:
        if re.search(r'ERROR|ORA-|CRITICAL|Exception|CRSeOns|Upload failed', line, re.I):
            raw = line
        else:
            return None
    et = classify_error_type(raw)
    norm = normalize_error_message(raw)
    fp = compute_fingerprint(raw, et)
    return raw, et, fp, norm