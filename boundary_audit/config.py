"""Configuration loading with safe, explicit defaults."""

from pathlib import Path
from typing import Any, Dict

import yaml


DEFAULT_CONFIG: Dict[str, Any] = {
    "gateway": {
        "upstream_interface": "eth0",
        "dut_interface": "wlan0",
        "dut_subnet": "10.77.0.0/24",
        "gateway_ip": "10.77.0.1",
    },
    "simulator": {"seed": 1337, "dut_ip": "10.77.0.2"},
}


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = yaml.safe_load(handle) or {}
    if not isinstance(value, dict):
        raise ValueError("configuration root must be a mapping")
    return value


def load_config(path: Path = Path("config.yaml")) -> Dict[str, Any]:
    if not path.exists():
        return DEFAULT_CONFIG.copy()
    result = DEFAULT_CONFIG.copy()
    loaded = load_yaml(path)
    for key, value in loaded.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = dict(result[key], **value)
        else:
            result[key] = value
    return result

