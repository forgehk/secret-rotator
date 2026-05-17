"""Verifiers confirm a new credential actually works."""

from __future__ import annotations

from typing import Protocol


class Verifier(Protocol):
    name: str
    def verify(self, secret: str) -> bool: ...


class AlwaysOKVerifier:
    name = "always_ok"
    def verify(self, secret: str) -> bool:
        return True


class AlwaysFailVerifier:
    name = "always_fail"
    def verify(self, secret: str) -> bool:
        return False
