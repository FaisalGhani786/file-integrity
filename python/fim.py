#!/usr/bin/env python3
"""File integrity monitor.

Creates a SHA-256 baseline of a folder, checks the folder against it later, or
watches it live. The baseline JSON format is shared with the browser version at
https://faisalghani786.github.io/file-integrity/

    python fim.py baseline ./site -o baseline.json
    python fim.py check ./site -m baseline.json
    python fim.py watch ./site -m baseline.json      # needs: pip install watchdog
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

TOOL = "file-integrity"
VERSION = 1
DEFAULT_IGNORE = {".git", "__pycache__", "node_modules", ".DS_Store"}
CHUNK = 1024 * 1024

SCRIPT_RE = re.compile(r"\.(php\d?|phtml|jsp|aspx?|cgi|pl|py|sh|exe|dll|ps1|bat)$")
CONFIG_RE = re.compile(
    r"(^|/)(\.htaccess|\.env|web\.config|wp-config\.php|config\.(php|js|json|ya?ml|ini)|"
    r"settings\.(py|php)|nginx\.conf|httpd\.conf|crontab|authorized_keys|passwd|shadow)$"
)
UPLOAD_RE = re.compile(r"(^|/)(uploads?|images?|media|tmp|cache|static)/")


def hash_file(path: Path) -> str:
    """SHA-256 of a file, read in chunks so large files don't fill memory."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def iter_files(root: Path, ignore: set[str]):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in ignore)
        for name in sorted(filenames):
            if name in ignore:
                continue
            p = Path(dirpath) / name
            if p.is_file() and not p.is_symlink():
                yield p


def build_manifest(root: Path, ignore: set[str] | None = None, created: str | None = None) -> dict:
    root = Path(root)
    ignore = DEFAULT_IGNORE if ignore is None else ignore
    files = {}
    for p in iter_files(root, ignore):
        rel = p.relative_to(root).as_posix()
        files[rel] = {"sha256": hash_file(p), "size": p.stat().st_size}
    return {
        "tool": TOOL,
        "version": VERSION,
        "algorithm": "sha256",
        "created": created or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "root": root.resolve().name,
        "files": dict(sorted(files.items())),
    }


def validate_manifest(m: dict) -> dict:
    if not isinstance(m, dict):
        raise ValueError("This isn't a baseline file: it doesn't contain a JSON object.")
    if m.get("tool") != TOOL:
        raise ValueError("This JSON wasn't created by File Integrity Monitor.")
    if m.get("version") != VERSION:
        raise ValueError(f"Unsupported baseline version {m.get('version')}. Expected {VERSION}.")
    if m.get("algorithm") != "sha256":
        raise ValueError(f"Unsupported hash algorithm {m.get('algorithm')!r}.")
    if not isinstance(m.get("files"), dict):
        raise ValueError("The baseline has no file list.")
    for path, f in m["files"].items():
        if not re.fullmatch(r"[0-9a-f]{64}", str((f or {}).get("sha256", ""))):
            raise ValueError(f"{path!r} has an invalid SHA-256 hash.")
    return m


def severity(path: str, kind: str) -> str:
    p = path.lower()
    name = p.rsplit("/", 1)[-1]
    script = bool(SCRIPT_RE.search(name))
    config = bool(CONFIG_RE.search(p))
    if kind == "added" and script and UPLOAD_RE.search(p):
        return "critical"
    if config and kind != "unchanged":
        return "high"
    if script and kind == "added":
        return "high"
    if kind == "removed" and re.search(r"(^|/)(robots\.txt|security\.txt|\.htaccess)$", p):
        return "medium"
    if kind == "unchanged":
        return "none"
    return "medium" if script else "low"


def compare(base: dict, cur: dict) -> dict:
    b, c = base["files"], cur["files"]
    result = {"unchanged": [], "modified": [], "added": [], "removed": []}
    for path in sorted(b):
        if path not in c:
            result["removed"].append({"path": path, "severity": severity(path, "removed")})
        elif b[path]["sha256"] != c[path]["sha256"]:
            result["modified"].append({"path": path, "severity": severity(path, "modified")})
        else:
            result["unchanged"].append({"path": path})
    for path in sorted(c):
        if path not in b:
            result["added"].append({"path": path, "severity": severity(path, "added")})
    result["clean"] = not (result["modified"] or result["added"] or result["removed"])
    return result


def load_manifest(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return validate_manifest(json.load(f))


def report(result: dict, out=sys.stdout) -> None:
    rows = [("MODIFIED", r) for r in result["modified"]] + [("ADDED", r) for r in result["added"]] + \
           [("REMOVED", r) for r in result["removed"]]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rows.sort(key=lambda x: order.get(x[1]["severity"], 9))
    if not rows:
        print(f"OK: {len(result['unchanged'])} files match the baseline.", file=out)
        return
    print(f"{'SEVERITY':<10} {'CHANGE':<9} PATH", file=out)
    for kind, r in rows:
        print(f"{r['severity'].upper():<10} {kind:<9} {r['path']}", file=out)
    print(f"\n{len(rows)} change(s), {len(result['unchanged'])} unchanged.", file=out)


def watch(root: Path, base: dict) -> None:  # pragma: no cover - needs a live filesystem
    try:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError:
        sys.exit("Watch mode needs watchdog. Install it with: pip install watchdog")

    root = Path(root).resolve()

    class Handler(FileSystemEventHandler):
        def on_any_event(self, event):
            if event.is_directory:
                return
            for raw in {getattr(event, "src_path", None), getattr(event, "dest_path", None)} - {None}:
                p = Path(raw)
                try:
                    rel = p.relative_to(root).as_posix()
                except ValueError:
                    continue
                if any(part in DEFAULT_IGNORE for part in Path(rel).parts):
                    continue
                stamp = datetime.now().strftime("%H:%M:%S")
                known = base["files"].get(rel)
                if p.exists() and p.is_file():
                    digest = hash_file(p)
                    if known is None:
                        kind = "ADDED"
                    elif known["sha256"] != digest:
                        kind = "MODIFIED"
                    else:
                        continue
                elif known is not None:
                    kind = "REMOVED"
                else:
                    continue
                sev = severity(rel, kind.lower())
                print(f"[{stamp}] {sev.upper():<8} {kind:<8} {rel}", flush=True)

    obs = Observer()
    obs.schedule(Handler(), str(root), recursive=True)
    obs.start()
    print(f"Watching {root} against the baseline. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        obs.stop()
    obs.join()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="SHA-256 file integrity monitor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("baseline", help="hash every file in a folder and save a baseline")
    b.add_argument("root", type=Path)
    b.add_argument("-o", "--output", type=Path, default=Path("baseline.json"))
    c = sub.add_parser("check", help="compare a folder with a saved baseline")
    c.add_argument("root", type=Path)
    c.add_argument("-m", "--manifest", type=Path, default=Path("baseline.json"))
    c.add_argument("--json", action="store_true", help="print the result as JSON")
    w = sub.add_parser("watch", help="report changes live as they happen")
    w.add_argument("root", type=Path)
    w.add_argument("-m", "--manifest", type=Path, default=Path("baseline.json"))
    args = ap.parse_args(argv)

    if not args.root.is_dir():
        print(f"{args.root} is not a folder.", file=sys.stderr)
        return 2
    if args.cmd == "baseline":
        m = build_manifest(args.root)
        args.output.write_text(json.dumps(m, indent=2) + "\n", encoding="utf-8")
        print(f"Baseline saved to {args.output}: {len(m['files'])} files hashed.")
        return 0
    try:
        base = load_manifest(args.manifest)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"Couldn't read the baseline: {e}", file=sys.stderr)
        return 2
    if args.cmd == "check":
        result = compare(base, build_manifest(args.root, created=base["created"]))
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            report(result)
        return 0 if result["clean"] else 1
    watch(args.root, base)
    return 0


if __name__ == "__main__":
    sys.exit(main())
