"""secret-rotator CLI (mock providers only — real ones plug in via the same API)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .audit import verify_log
from .engine import RotationEngine
from .providers import MockProvider
from .stores import MockStore
from .verifiers import AlwaysFailVerifier, AlwaysOKVerifier


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="secret-rotator")
    sub = p.add_subparsers(dest="cmd", required=True)

    demo = sub.add_parser("demo", help="Run a mock rotation end-to-end.")
    demo.add_argument("--fail-verify", action="store_true",
                      help="Force the verify step to fail so you can see rollback.")
    demo.add_argument("--audit", type=Path, default=Path("./audit.jsonl"))

    audit = sub.add_parser("audit", help="Inspect the audit log.")
    audit_sub = audit.add_subparsers(dest="audit_cmd", required=True)
    verify = audit_sub.add_parser("verify", help="Check the audit log's hash chain.")
    verify.add_argument("--audit", type=Path, default=Path("./audit.jsonl"))

    args = p.parse_args(argv)
    if args.cmd == "audit":
        if not args.audit.exists():
            print(f"no audit log at {args.audit}", file=sys.stderr)
            return 2
        report = verify_log(args.audit)
        if report.ok:
            print(f"audit log OK: {report.entries} records, chain intact")
            return 0
        print(f"audit log BROKEN at line {report.bad_line}: {report.reason} "
              f"({report.entries} records verified before it)")
        return 1
    if args.cmd == "demo":
        engine = RotationEngine(
            key_name="demo_key",
            provider=MockProvider(),
            store=MockStore({"/app/demo": "old-secret-value"}),
            store_path="/app/demo",
            verifier=(AlwaysFailVerifier() if args.fail_verify else AlwaysOKVerifier()),
            grace_seconds=0,
            audit_log_path=args.audit,
        )
        result = engine.rotate()
        for s in result.steps:
            marker = "OK  " if s.ok else "FAIL"
            print(f"  [{marker}] {s.name:<22} {s.detail}")
        print()
        if result.succeeded:
            print(f"rotation OK — audit appended to {args.audit}")
            return 0
        else:
            print(f"rotation FAILED (rolled back). audit at {args.audit}")
            return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
