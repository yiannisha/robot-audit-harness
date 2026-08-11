"""Device adapter boundary. The auditor only knows this interface."""

from abc import ABC, abstractmethod
from typing import Any, Dict

from pydantic import BaseModel

from .models import ActionSpec


class HealthResult(BaseModel):
    ok: bool
    status_code: int = 200
    detail: str = ""


class ActionResult(BaseModel):
    ok: bool
    status_code: int
    detail: str = ""
    response: Dict[str, Any] = {}


class DeviceAdapter(ABC):
    @abstractmethod
    def reset(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def health(self) -> HealthResult:
        raise NotImplementedError

    @abstractmethod
    def execute(self, action: ActionSpec) -> ActionResult:
        raise NotImplementedError

    @abstractmethod
    def cleanup(self) -> None:
        raise NotImplementedError

