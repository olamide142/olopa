#!/usr/bin/env python3
"""Prove the preload guard skips real PostgreSQL/MySQL client functions."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "agent" / "sql_guard" / "tests" / "fixtures"
GUARD = ROOT / "agent" / "target" / "debug" / "libolopa_sql_guard.so"


def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, text=True, **kwargs)


def main() -> int:
    run(
        [
            "cargo",
            "build",
            "--manifest-path",
            str(ROOT / "agent" / "Cargo.toml"),
            "-p",
            "olopa-sql-guard",
        ],
        cwd=ROOT,
    )

    with tempfile.TemporaryDirectory(prefix="olopa-sql-guard-") as temporary:
        work = Path(temporary)
        library = work / "libfakedb.so"
        client = work / "guard-client"
        marker = work / "called.txt"
        run(
            [
                "cc",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-shared",
                "-fPIC",
                str(FIXTURES / "fake_db.c"),
                "-o",
                str(library),
            ]
        )
        run(
            [
                "cc",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(FIXTURES / "guard_client.c"),
                "-L",
                str(work),
                "-lfakedb",
                f"-Wl,-rpath,{work}",
                "-o",
                str(client),
            ]
        )

        cases = {
            "pqexec": ("1", "0"),
            "pqparams": ("1", "0"),
            "pqsend": ("1", "0"),
            "pqsendparams": ("1", "0"),
            "pqprepared": ("1", "0"),
            "pqsendprepared": ("1", "0"),
            "mysqlreal": ("0", "1"),
            "mysqlquery": ("0", "1"),
            "mysqlprepared": ("0", "1"),
        }

        for name, (allowed_result, blocked_result) in cases.items():
            base_env = {
                **os.environ,
                "LD_PRELOAD": str(GUARD),
                "OLOPA_SQL_POLICY_SOCKET": str(work / "missing.sock"),
                "OLOPA_SQL_GUARD_MARKER": str(marker),
            }

            marker.unlink(missing_ok=True)
            allowed = run([str(client), name], env=base_env, capture_output=True)
            if allowed.stdout.strip() != allowed_result or not marker.exists():
                raise RuntimeError(f"fail-open case did not reach real function: {name}")

            marker.unlink(missing_ok=True)
            blocked = run(
                [str(client), name],
                env={**base_env, "OLOPA_SQL_GUARD_FAIL_CLOSED": "1"},
                capture_output=True,
            )
            if blocked.stdout.strip() != blocked_result or marker.exists():
                raise RuntimeError(f"blocked case reached real function: {name}")

    print(f"SQL guard smoke passed ({len(cases)} client API paths)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
