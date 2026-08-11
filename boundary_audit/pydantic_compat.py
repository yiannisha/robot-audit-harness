"""Compatibility helpers for projects supporting both Pydantic v1 and v2."""

from typing import Any


def model_dump(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "dict"):
        return value.dict()
    return value
