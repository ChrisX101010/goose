#!/usr/bin/env python3
"""Check offline package resolution and prepare local human-review evidence."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


PROBE = "goose-check-offline"
EXPECTED = {"cold": "rejected", "warm": "accepted"}
RESULTS = {"accepted", "rejected", "git-invoked", "unexpected-result", "inconclusive"}
PATCH_PATHS = {"src/packages.h", "test/packages_git.py", "docs/testing.md"}
LIMIT = 64 * 1024


def run(args, **kwargs):
    return subprocess.run(args, capture_output=True, timeout=30, **kwargs)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def commit_id(value):
    if not re.fullmatch("[0-9a-f]{40}", value):
        raise ValueError("expected a full lowercase Git commit ID")
    return value


def classify(checks):
    if any(value not in {EXPECTED[name], "inconclusive"} for name, value in checks.items()):
        return "regression"
    if checks == EXPECTED:
        return "pass"
    return "inconclusive"


def save(path, data):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(data, stream, sort_keys=True, indent=2)
        stream.write("\n")


def probe(exe, commit, out):
    commit_id(commit)
    exe = exe.resolve(strict=True)
    compiler_hash = digest(exe.read_bytes())
    checks = dict.fromkeys(EXPECTED, "inconclusive")
    with tempfile.TemporaryDirectory(prefix="goose-offline-") as tmp:
        base = Path(tmp).resolve()
        home = base / "home"
        trace = base / "git-trace.jsonl"
        program = base / "main.goose"
        program.write_text(
            'import gitpkg from "https://offline.invalid/example/gitpkg.git@v1";\n'
            'fn main() { print(gitpkg::code()); }\n',
            encoding="utf-8",
        )
        env = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR")
               if key in os.environ}
        env.update(HOME=str(home), USERPROFILE=str(home), GOOSE_HOME=str(home),
                   TMP=str(base), TEMP=str(base), TMPDIR=str(base),
                   GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_TRACE2_EVENT=str(trace), GIT_ALLOW_PROTOCOL="")
        try:
            control = run(["git", "--version"], cwd=base, env=env)
            if control.returncode == 0 and trace.is_file() and trace.stat().st_size:
                trace.unlink()
                for name in EXPECTED:
                    if name == "warm":
                        cached = home / "pkg/offline.invalid/example/gitpkg/v1"
                        cached.mkdir(parents=True, exist_ok=True)
                        (cached / "gitpkg.goose").write_text(
                            "namespace gitpkg;\nfn code() -> i64 { 42 }\n",
                            encoding="utf-8",
                        )
                    trace.unlink(missing_ok=True)
                    result = run([str(exe), "check", "--offline", str(program)],
                                 cwd=base, env=env)
                    if trace.exists():
                        checks[name] = "git-invoked"
                    elif result.returncode == 0:
                        checks[name] = "accepted"
                    elif result.returncode == 1 and b"is not fetched" in result.stderr:
                        checks[name] = "rejected"
                    else:
                        checks[name] = "unexpected-result"
        except (OSError, subprocess.TimeoutExpired):
            pass

    status = classify(checks)
    save(out, {"schema": 1, "probe": PROBE, "commit": commit,
               "compiler_sha256": compiler_hash, "checks": checks, "status": status})
    return {"pass": 0, "regression": 1, "inconclusive": 2}[status]


def limited_read(path):
    with path.open("rb") as stream:
        data = stream.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError("input exceeds 64 KiB")
    return data


def review(repo, evidence, candidate, out):
    raw = limited_read(evidence)
    record = json.loads(raw)
    fields = {"schema", "probe", "commit", "compiler_sha256", "checks", "status"}
    if not isinstance(record, dict) or set(record) != fields:
        raise ValueError("invalid report fields")
    checks = record["checks"]
    if (type(record["schema"]) is not int or record["schema"] != 1 or
            record["probe"] != PROBE or
            not isinstance(checks, dict) or set(checks) != set(EXPECTED) or
            any(not isinstance(v, str) or v not in RESULTS for v in checks.values()) or
            record["status"] != "regression" or classify(checks) != "regression"):
        raise ValueError("report is not a confirmed probe regression")
    commit = commit_id(record["commit"])
    if not re.fullmatch("[0-9a-f]{64}", record["compiler_sha256"]):
        raise ValueError("invalid compiler SHA-256")

    def git(*args, **kwargs):
        return run(["git", "-c", "core.fsmonitor=false", "-C", str(repo), *args], **kwargs)

    head = git("rev-parse", "--verify", "HEAD^{commit}")
    dirty = git("status", "--porcelain=v1")
    if head.returncode or head.stdout.strip().decode("ascii") != commit:
        raise ValueError("checkout HEAD differs from the report commit")
    if dirty.returncode or dirty.stdout:
        raise ValueError("review requires a clean checkout")

    patch_info = None
    if candidate:
        patch = limited_read(candidate)
        stat = git("apply", "--numstat", "-z", "-", input=patch)
        entries = stat.stdout.split(b"\0")
        paths = []
        for entry in entries[:-1]:
            columns = entry.decode("utf-8").split("\t", 2)
            if len(columns) != 3 or not all(n.isdecimal() for n in columns[:2]):
                raise ValueError("candidate uses an unsupported patch format")
            paths.append(columns[2])
        if stat.returncode or not paths or not set(paths) <= PATCH_PATHS:
            raise ValueError("candidate touches paths outside this review")
        if git("apply", "--check", "--index", "-", input=patch).returncode:
            raise ValueError("candidate does not apply to the reported commit")
        patch_info = {"sha256": digest(patch), "paths": sorted(set(paths))}

    save(out, {"schema": 1, "state": "human-review-required", "probe": PROBE,
               "commit": commit, "checks": checks, "evidence_sha256": digest(raw),
               "candidate": patch_info})
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check")
    check.add_argument("--exe", type=Path, required=True)
    check.add_argument("--commit", required=True)
    check.add_argument("--out", type=Path, required=True)
    handoff = sub.add_parser("review")
    handoff.add_argument("--repo", type=Path, required=True)
    handoff.add_argument("--evidence", type=Path, required=True)
    handoff.add_argument("--candidate", type=Path)
    handoff.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "check":
            return probe(args.exe, args.commit, args.out)
        return review(args.repo.resolve(strict=True), args.evidence, args.candidate, args.out)
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired) as error:
        parser.exit(2, f"error: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
