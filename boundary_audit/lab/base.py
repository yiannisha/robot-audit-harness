"""Backend lifecycle contract."""

from abc import ABC, abstractmethod


class LabBackend(ABC):
    @abstractmethod
    def up(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def status(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def down(self) -> None:
        raise NotImplementedError
