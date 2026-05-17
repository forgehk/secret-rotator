"""Provider protocol + a mock for tests / dry runs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class Credential:
    id: str
    secret: str
    metadata: dict


class Provider(Protocol):
    name: str

    def provision(self) -> Credential:
        """Create a new credential at the provider."""
        ...

    def revoke(self, credential_id: str) -> None:
        """Deactivate / delete a credential."""
        ...


class MockProvider:
    """In-memory provider for tests and dry-runs."""

    name = "mock"

    def __init__(self) -> None:
        self._counter = 0
        self.live: set[str] = set()

    def provision(self) -> Credential:
        self._counter += 1
        cid = f"mock-key-{self._counter:04d}"
        self.live.add(cid)
        return Credential(
            id=cid,
            secret=f"secret-{self._counter:04d}",
            metadata={"provider": "mock"},
        )

    def revoke(self, credential_id: str) -> None:
        self.live.discard(credential_id)
