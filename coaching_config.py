"""
Coaching Review configuration management.
Reads/writes config from /etc/gravae/coaching-review.json
"""
import json
import os

try:
    from gravae_logging import get_logger
    log = get_logger('config')
except ImportError:
    import logging
    log = logging.getLogger('config')

CONFIG_PATH = "/etc/gravae/coaching-review.json"

_config = None


def load_config():
    """Load coaching config from disk."""
    global _config
    try:
        with open(CONFIG_PATH, 'r') as f:
            _config = json.load(f)
    except Exception:
        _config = {}
    return _config


def get_config():
    """Get current config (loads from disk if not loaded yet)."""
    global _config
    if _config is None:
        load_config()
    return _config


def save_config(config=None):
    """Save coaching config to disk."""
    global _config
    if config is not None:
        _config = config
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, 'w') as f:
            json.dump(_config, f, indent=2)
        return True
    except Exception as e:
        log.error(f"Failed to save config: {e}")
        return False


def is_configured():
    """Check if coaching review is configured with minimum required fields."""
    cfg = get_config()
    return bool(cfg.get('apiUrl') and cfg.get('deviceToken') and cfg.get('deviceId'))


def update_config(data):
    """Update config fields and save."""
    cfg = get_config()
    updated = []
    allowed_fields = [
        'apiUrl', 'deviceToken', 'deviceId',
        'shinobiApiKey', 'shinobiGroupKey', 'shinobiEmail', 'shinobiPassword',
        'r2Endpoint', 'r2AccessKeyId', 'r2SecretAccessKey',
        'r2BucketMaster', 'r2BucketProxy',
        'uploadThrottleBytesPerSec', 'uploadPartSizeBytes',
    ]
    for field in allowed_fields:
        if field in data:
            cfg[field] = data[field]
            updated.append(field)
    if updated:
        save_config(cfg)
    return updated
