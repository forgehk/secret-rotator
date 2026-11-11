"""Tests for the hash-chained audit log and `secret-rotator audit verify`."""

import json
from pathlib import Path

from secret_rotator.audit import GENESIS, record_hash, verify_log
from secret_rotator.cli import main
from secret_rotator.engine import RotationEngine
from secret_rotator.providers import MockProvider
from secret_rotator.stores import MockStore
from secret_rotator.verifiers import AlwaysFailVerifier, AlwaysOKVerifier


def _rotate(audit: Path, verifier=None) -> None:
    RotationEngine(
        key_name="demo",
        provider=MockProvider(),
        store=MockStore({"/path": "old-secret"}),
        store_path="/path",
        verifier=verifier or AlwaysOKVerifier(),
        grace_seconds=0,
        audit_log_path=audit,
    ).rotate()


def _records(audit: Path) -> list[dict]:
    return [json.loads(line) for line in audit.read_text().splitlines()]


def _write(audit: Path, records: list[dict]) -> None:
    audit.write_text("".join(json.dumps(r) + "\n" for r in records))


def test_records_are_chained(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    _rotate(audit)
    _rotate(audit, AlwaysFailVerifier())
    _rotate(audit)
    recs = _records(audit)
    assert recs[0]["prev"] == GENESIS
    assert recs[1]["prev"] == recs[0]["hash"]
    assert recs[2]["prev"] == recs[1]["hash"]
    for r in recs:
        assert r["hash"] == record_hash(r)
    report = verify_log(audit)
    assert report.ok and report.entries == 3


def test_dry_run_writes_one_record(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    RotationEngine(
        key_name="demo",
        provider=MockProvider(),
        store=MockStore({"/path": "old-secret"}),
        store_path="/path",
        verifier=AlwaysOKVerifier(),
        audit_log_path=audit,
    ).rotate(dry_run=True)
    recs = _records(audit)
    assert len(recs) == 1
    assert recs[0]["succeeded"] is True
    assert verify_log(audit).ok


def test_modified_record_is_detected(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    for _ in range(3):
        _rotate(audit)
    recs = _records(audit)
    recs[1]["succeeded"] = False
    _write(audit, recs)
    report = verify_log(audit)
    assert not report.ok
    assert report.bad_line == 2
    assert report.entries == 1
    assert "modified" in report.reason


def test_removed_record_is_detected(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    for _ in range(3):
        _rotate(audit)
    recs = _records(audit)
    _write(audit, [recs[0], recs[2]])
    report = verify_log(audit)
    assert not report.ok
    assert report.bad_line == 2
    assert "removed or reordered" in report.reason


def test_reordered_records_are_detected(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    for _ in range(2):
        _rotate(audit)
    recs = _records(audit)
    _write(audit, [recs[1], recs[0]])
    report = verify_log(audit)
    assert not report.ok
    assert report.bad_line == 1


def test_unchained_record_is_rejected(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    audit.write_text(json.dumps({"key": "demo", "succeeded": True}) + "\n")
    report = verify_log(audit)
    assert not report.ok
    assert "missing prev/hash" in report.reason


def test_rotation_still_logs_after_an_unchained_line(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    audit.write_text(json.dumps({"key": "legacy", "succeeded": True}) + "\n")
    _rotate(audit)
    recs = _records(audit)
    assert len(recs) == 2
    assert recs[1]["prev"] == GENESIS
    assert recs[1]["hash"] == record_hash(recs[1])
    assert verify_log(audit).bad_line == 1


def test_empty_log_verifies(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    audit.write_text("")
    report = verify_log(audit)
    assert report.ok and report.entries == 0


def test_cli_verify_exit_codes(tmp_path: Path, capsys) -> None:
    audit = tmp_path / "audit.jsonl"
    assert main(["demo", "--audit", str(audit)]) == 0
    assert main(["demo", "--fail-verify", "--audit", str(audit)]) == 1
    capsys.readouterr()

    assert main(["audit", "verify", "--audit", str(audit)]) == 0
    assert "2 records, chain intact" in capsys.readouterr().out

    recs = _records(audit)
    recs[0]["rolled_back"] = True
    _write(audit, recs)
    assert main(["audit", "verify", "--audit", str(audit)]) == 1
    assert "BROKEN at line 1" in capsys.readouterr().out

    assert main(["audit", "verify", "--audit", str(tmp_path / "missing.jsonl")]) == 2
