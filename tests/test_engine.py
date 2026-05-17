"""Tests for the rotation engine — happy path + rollback."""

from pathlib import Path

from secret_rotator.engine import RotationEngine
from secret_rotator.providers import MockProvider
from secret_rotator.stores import MockStore
from secret_rotator.verifiers import AlwaysFailVerifier, AlwaysOKVerifier


def _engine(verifier, audit_path: Path):
    return RotationEngine(
        key_name="demo",
        provider=MockProvider(),
        store=MockStore({"/path": "old-secret"}),
        store_path="/path",
        verifier=verifier,
        grace_seconds=0,
        audit_log_path=audit_path,
    )


def test_happy_path_updates_store(tmp_path: Path) -> None:
    e = _engine(AlwaysOKVerifier(), tmp_path / "audit.jsonl")
    r = e.rotate()
    assert r.succeeded is True
    assert r.rolled_back is False
    assert e.store.get("/path") != "old-secret"
    assert r.new_credential_id is not None


def test_verify_failure_triggers_rollback(tmp_path: Path) -> None:
    e = _engine(AlwaysFailVerifier(), tmp_path / "audit.jsonl")
    r = e.rotate()
    assert r.succeeded is False
    assert r.rolled_back is True
    # Store should be back to the original value
    assert e.store.get("/path") == "old-secret"


def test_dry_run_does_not_touch_store(tmp_path: Path) -> None:
    e = _engine(AlwaysOKVerifier(), tmp_path / "audit.jsonl")
    r = e.rotate(dry_run=True)
    assert r.succeeded is True
    assert e.store.get("/path") == "old-secret"


def test_audit_log_appended(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    e = _engine(AlwaysOKVerifier(), audit)
    e.rotate()
    lines = audit.read_text().strip().splitlines()
    assert len(lines) == 1
    assert "demo" in lines[0]
    assert "succeeded" in lines[0]


def test_provider_revokes_new_on_failure(tmp_path: Path) -> None:
    e = _engine(AlwaysFailVerifier(), tmp_path / "audit.jsonl")
    r = e.rotate()
    # MockProvider tracks live credentials; failed rotation should have revoked the new one.
    assert len(e.provider.live) == 0
    assert r.rolled_back is True
