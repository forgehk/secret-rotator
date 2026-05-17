"""Secret-store protocol + a mock implementation."""

from __future__ import annotations

from typing import Protocol


class SecretStore(Protocol):
    name: str

    def get(self, path: str) -> str | None: ...
    def set(self, path: str, value: str) -> None: ...


class MockStore:
    """In-memory store keyed by path."""

    name = "mock"

    def __init__(self, initial: dict[str, str] | None = None) -> None:
        self._data: dict[str, str] = dict(initial or {})

    def get(self, path: str) -> str | None:
        return self._data.get(path)

    def set(self, path: str, value: str) -> None:
        self._data[path] = value

    def snapshot(self) -> dict[str, str]:
        return dict(self._data)
