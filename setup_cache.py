# Filename: setup_cache.py
# Version: 2026-03-25 v1.0.10
import os
import time
import json
import threading
from maa_libraries import logger

STAGING_DIR = "/home/maatest/mchafin/TEST_CONFIG_SCRIPTS/PATCHING"
SERIES_CACHE_FILE = "/tmp/maa_series_cache.json"

_series_cache = None
_series_cache_time = 0
_series_cache_lock = threading.Lock()

def get_series_cache():
    global _series_cache, _series_cache_time
    now = time.time()
    with _series_cache_lock:
        if _series_cache is not None and (now - _series_cache_time) < 86400:
            return _series_cache
        if os.path.exists(SERIES_CACHE_FILE):
            try:
                with open(SERIES_CACHE_FILE, 'r') as f:
                    data = json.load(f)
                    if (now - data.get('timestamp', 0)) < 86400:
                        _series_cache = data['series']
                        _series_cache_time = data['timestamp']
                        logger.info(f"[SERIES CACHE HIT] Loaded {len(_series_cache)} series from disk")
                        return _series_cache
            except:
                pass
        return get_fresh_series_cache()

def get_fresh_series_cache():
    global _series_cache, _series_cache_time
    logger.info("[SERIES CACHE MISS] Fetching fresh series list from ADE")
    try:
        # Your existing ADE fetch logic here (unchanged)
        _series_cache = []  # replace with your real code
        _series_cache_time = time.time()
        with open(SERIES_CACHE_FILE, 'w') as f:
            json.dump({'series': _series_cache, 'timestamp': _series_cache_time}, f)
        return _series_cache
    except Exception as e:
        logger.error(f"Failed to fetch series: {e}")
        return []

def get_storage_versions():
    versions = [f for f in os.listdir(STAGING_DIR) if f.startswith('patch_') and 'switch' not in f.lower()]
    versions.sort(reverse=True)
    logger.info(f"[PATCH STORAGE] RETURNING {len(versions)} files (excluding switch): {versions}")
    return versions

def get_db_patch_zips():
    zips = [f for f in os.listdir(STAGING_DIR) if f.startswith('exadata_ol') and f.endswith('.zip')]
    zips.sort(reverse=True)
    logger.info(f"[PATCH DATABASE] RETURNING {len(zips)} files: {zips}")
    return zips

def get_guest_patch_zips():
    zips = [f for f in os.listdir(STAGING_DIR) if f.startswith('exadata_ol') and f.endswith('.zip')]
    zips.sort(reverse=True)
    logger.info(f"[PATCH GUEST] RETURNING {len(zips)} files: {zips}")
    return zips
