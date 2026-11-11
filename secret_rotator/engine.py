"""Rotation engine: orchestrates snapshot → provision → store → verify → revoke.

If any step fails, the run aborts and rollback restores the previous key
from the snapshot.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .audit import chain, last_hash
from .providers import Credential, Provider
from .stores import SecretStore
from .verifiers import Verifier


class RotationError(Exception):
    """Raised when a rotation step fails after rollback has been attempted."""


@dataclass
class Step:
    name: str
    ok: bool
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"step": self.name, "ok": self.ok, "detail": self.detail}


@dataclass
class RotationResult:
    key_name: str
    succeeded: bool
    steps: list[Step] = field(default_factory=list)
    rolled_back: bool = False
    new_credential_id: str | None = None
    audit_lines: list[str] = field(default_factory=list)


class RotationEngine:
    """A single rotation orchestrator. One instance per `keys` entry."""

    def __init__(
        self,
        *,
        key_name: str,
        provider: Provider,
        store: SecretStore,
        store_path: str,
        verifier: Verifier,
        grace_seconds: int = 0,
        audit_log_path: Path | None = None,
    ) -> None:
        self.key_name = key_name
        self.provider = provider
        self.store = store
        self.store_path = store_path
        self.verifier = verifier
        self.grace_seconds = grace_seconds
        self.audit_log_path = audit_log_path

    def rotate(self, *, dry_run: bool = False) -> RotationResult:
        result = RotationResult(key_name=self.key_name, succeeded=False)
        old_secret = self.store.get(self.store_path)
        old_credential_id: str | None = None  # provider can't always discover this; tracked separately

        self._step(result, "snapshot",
                   detail=f"prev value len={len(old_secret) if old_secret else 0}")

        new_cred: Credential | None = None
        try:
            # 1. Provision new credential
            if dry_run:
                self._step(result, "provision", detail="(dry-run) would call provider.provision()")
                result.succeeded = True
                return result
            new_cred = self.provider.provision()
            old_credential_id = new_cred.metadata.get("old_id")  # informational
            result.new_credential_id = new_cred.id
            self._step(result, "provision", detail=f"new id={new_cred.id}")

            # 2. Update store
            self.store.set(self.store_path, new_cred.secret)
            self._step(result, "update_store", detail=f"path={self.store_path}")

            # 3. Verify
            if not self.verifier.verify(new_cred.secret):
                raise RuntimeError(f"verifier {self.verifier.name} returned false")
            self._step(result, "verify", detail=f"verifier={self.verifier.name}")

            # 4. Grace period for downstream pickup
            if self.grace_seconds:
                time.sleep(self.grace_seconds)
            self._step(result, "grace", detail=f"waited {self.grace_seconds}s")

            # 5. Revoke old (only if we know its id)
            if old_credential_id:
                self.provider.revoke(old_credential_id)
                self._step(result, "revoke_old", detail=f"revoked id={old_credential_id}")
            else:
                self._step(result, "revoke_old", detail="no old id known, skipped")

            result.succeeded = True
        except Exception as exc:
            # Rollback
            if old_secret is not None:
                self.store.set(self.store_path, old_secret)
                self._step(result, "rollback_store", detail="restored previous secret")
            if new_cred is not None:
                try:
                    self.provider.revoke(new_cred.id)
                    self._step(result, "rollback_revoke_new",
                               detail=f"revoked new id={new_cred.id}")
                except Exception as rexc:
                    self._step(result, "rollback_revoke_new", ok=False,
                               detail=f"revoke failed: {rexc}")
            self._step(result, "abort", ok=False, detail=str(exc))
            result.rolled_back = True
        finally:
            self._emit_audit(result)
        return result

    def _step(self, result: RotationResult, name: str, *, ok: bool = True, detail: str = "") -> None:
        result.steps.append(Step(name=name, ok=ok, detail=detail))

    def _emit_audit(self, result: RotationResult) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "key": self.key_name,
            "succeeded": result.succeeded,
            "rolled_back": result.rolled_back,
            "new_credential_id": result.new_credential_id,
            "steps": [s.to_dict() for s in result.steps],
        }
        record = chain(record, last_hash(self.audit_log_path))
        line = json.dumps(record)
        result.audit_lines.append(line)
        if self.audit_log_path is not None:
            self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_log_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
