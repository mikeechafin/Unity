# Version: 2026-06-28 v1.0.0
"""SSH connection pool for fleet agent log crawling."""
import logging
import os
from queue import Queue, Empty
from threading import Lock

import paramiko

import config
from maa_libraries import get_db_connection_standalone, get_credential_silent

logger = logging.getLogger(__name__)

REMOTE_USERS = ['oracle', 'root']
SSH_TIMEOUT = 15
SSH_BANNER_TIMEOUT = 5
SSH_RETRIES = 2

SSH_KEY_PATHS = [
    (config.SSH_KEY_PATH, 'ed25519'),
    ('/home/maatest/.ssh/id_rsa', 'rsa'),
    ('/home/maatest/.ssh/id_ecdsa', 'ecdsa'),
    ('/home/maatest/.ssh/id_ed25519', 'ed25519'),
]


def _load_ssh_keys():
    keys = []
    seen = set()
    for path, key_type in SSH_KEY_PATHS:
        if not path or path in seen or not os.path.isfile(path):
            continue
        seen.add(path)
        try:
            if key_type == 'rsa':
                key = paramiko.RSAKey.from_private_key_file(path)
            elif key_type == 'ecdsa':
                key = paramiko.ECDSAKey.from_private_key_file(path)
            else:
                key = paramiko.Ed25519Key.from_private_key_file(path)
            keys.append((key, os.path.basename(path)))
        except Exception as exc:
            logger.warning('Failed to load SSH key %s: %s', path, exc)
    return keys


SSH_KEYS = _load_ssh_keys()


class SSHConnectionPool:
    def __init__(self, max_size=50):
        self.pool = Queue(maxsize=max_size)
        self.lock = Lock()

    def get_client(self, hostname, component_type='GUEST'):
        with self.lock:
            try:
                client = self.pool.get_nowait()
                if client.get_transport() and client.get_transport().is_active():
                    return client
                client.close()
            except Empty:
                pass

            for _ in range(SSH_RETRIES):
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                connected = False
                for username in REMOTE_USERS:
                    for pkey, _ in SSH_KEYS:
                        try:
                            client.connect(
                                hostname, username=username, pkey=pkey,
                                timeout=SSH_TIMEOUT, banner_timeout=SSH_BANNER_TIMEOUT,
                                allow_agent=False, look_for_keys=False,
                            )
                            connected = True
                            break
                        except Exception:
                            pass
                    if connected:
                        break
                    conn = get_db_connection_standalone()
                    cursor = conn.cursor()
                    try:
                        password = get_credential_silent(cursor, component_type, hostname, username)
                        if not password:
                            password = get_credential_silent(cursor, component_type, 'default', username)
                        if password:
                            client.connect(
                                hostname, username=username, password=password,
                                timeout=SSH_TIMEOUT, banner_timeout=SSH_BANNER_TIMEOUT,
                            )
                            connected = True
                            break
                    finally:
                        cursor.close()
                        conn.close()
                if connected:
                    client.get_transport().set_keepalive(30)
                    return client
                client.close()
            return None

    def release_client(self, client):
        with self.lock:
            if client and self.pool.qsize() < self.pool.maxsize:
                transport = client.get_transport()
                if transport and transport.is_active():
                    self.pool.put(client)
                    return
            if client:
                client.close()


POOL = SSHConnectionPool()