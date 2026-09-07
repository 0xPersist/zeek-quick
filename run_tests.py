#!/usr/bin/env python3
"""
zeek-quick regression tests.

Focused on input handling. The documented compressed-log idiom
(`zcat conn.log.gz | zeek-quick - --type conn`) shipped broken because
parse_zeek_log rewound the handle with seek(0), which raises
io.UnsupportedOperation on a pipe. There was no test that fed a stream,
so nothing caught it. These pin that path.
"""
from __future__ import annotations

import gzip
import json
import os
import subprocess
import sys
import tempfile

_TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zeek_quick.py")
_passed = 0
_failed = 0


def check(label: str, cond: bool) -> None:
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  [PASS] {label}")
    else:
        _failed += 1
        print(f"  [FAIL] {label}")


def run(args, stdin_bytes=None):
    return subprocess.run(
        [sys.executable, _TOOL] + args,
        input=stdin_bytes,
        capture_output=True,
    )


FIXTURE = "\n".join([
    "#separator \\x09",
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes",
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount",
] + [
    f"{1700000000 + i*60}.0\tC{i}\t192.0.2.10\t4{i:04d}\t198.51.100.20\t443\ttcp\tssl\t1.0\t500\t1000"
    for i in range(40)
]) + "\n"

JSON_FIXTURE = "\n".join(
    json.dumps({"ts": 1700000000 + i * 60, "uid": f"C{i}", "id.orig_h": "192.0.2.10",
                "id.orig_p": 40000 + i, "id.resp_h": "198.51.100.20", "id.resp_p": 443,
                "proto": "tcp", "service": "ssl", "duration": 1.0,
                "orig_bytes": 500, "resp_bytes": 1000})
    for i in range(40)) + "\n"


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="zeek-quick-tests-")
    tsv = os.path.join(tmp, "conn.log")
    with open(tsv, "w") as fh:
        fh.write(FIXTURE)
    gz = os.path.join(tmp, "conn.log.gz")
    with gzip.open(gz, "wt") as fh:
        fh.write(FIXTURE)
    js = os.path.join(tmp, "conn_json.log")
    with open(js, "w") as fh:
        fh.write(JSON_FIXTURE)

    print("T1: file path baseline")
    base = run([tsv, "--type", "conn", "--json", "--no-banner"])
    check("file path exits 0", base.returncode == 0)
    check("file path parses records", b'"total_connections": 40' in base.stdout)

    print("T2: piped stdin (regression — this shipped broken)")
    raw = FIXTURE.encode()
    for arg in ("-", "/dev/stdin"):
        r = run([arg, "--type", "conn", "--json", "--no-banner"], stdin_bytes=raw)
        check(f"{arg} exits 0", r.returncode == 0)
        check(f"{arg} parses records", b'"total_connections": 40' in r.stdout)
        check(f"{arg} output identical to file path", r.stdout == base.stdout)
        check(f"{arg} no seek error", b"UnsupportedOperation" not in r.stderr)

    print("T3: the documented compressed-log idiom end to end")
    with gzip.open(gz, "rb") as fh:
        decompressed = gzip.decompress(open(gz, "rb").read())
    r = run(["-", "--type", "conn", "--json", "--no-banner"], stdin_bytes=decompressed)
    check("zcat-equivalent pipe parses", r.returncode == 0 and r.stdout == base.stdout)

    print("T4: JSON (NDJSON) over a pipe")
    jbase = run([js, "--type", "conn", "--json", "--no-banner"])
    jpipe = run(["-", "--type", "conn", "--json", "--no-banner"],
                stdin_bytes=JSON_FIXTURE.encode())
    check("ndjson file path parses", jbase.returncode == 0)
    check("ndjson pipe identical to file path", jpipe.stdout == jbase.stdout)

    print("T5: empty and malformed input do not crash")
    r = run(["-", "--type", "conn", "--json", "--no-banner"], stdin_bytes=b"")
    check("empty stdin exits cleanly", r.returncode in (0, 1) and b"Traceback" not in r.stderr)
    r = run(["-", "--type", "conn", "--json", "--no-banner"], stdin_bytes=b"not a zeek log\n")
    check("garbage stdin exits cleanly", b"Traceback" not in r.stderr)

    print("T6: missing file still reports cleanly")
    r = run([os.path.join(tmp, "nope.log"), "--type", "conn"])
    check("missing file, no traceback", b"Traceback" not in r.stderr)

    print(f"\nRESULTS: {_passed} passed, {_failed} failed")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
