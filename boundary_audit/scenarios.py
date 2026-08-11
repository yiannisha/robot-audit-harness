"""Human-readable scenario definitions and event timeline helpers."""

from pathlib import Path
from typing import Dict, List

import yaml

from .models import ActionCategory, ActionSpec


def load_scenario(path: Path) -> ActionSpec:
    with path.open(encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    return ActionSpec(
        name=raw["name"], category=ActionCategory(raw["category"]),
        parameters=raw.get("action", {}).get("parameters", {}),
        timeout_seconds=raw.get("action", {}).get("timeout_seconds", 5.0),
        baseline_seconds=raw.get("timing", {}).get("baseline_seconds", 1.0),
        observation_seconds=raw.get("timing", {}).get("observation_seconds", 1.0),
        cooldown_seconds=raw.get("timing", {}).get("cooldown_seconds", 0.2),
        repeats=raw.get("repeats", 1), expected_status=raw.get("success", {}).get("http_status", 200),
    )


def scenario_paths(root: Path) -> List[Path]:
    return sorted(root.glob("*.yaml"))


def load_all(root: Path) -> Dict[str, ActionSpec]:
    return {p.stem: load_scenario(p) for p in scenario_paths(root)}

