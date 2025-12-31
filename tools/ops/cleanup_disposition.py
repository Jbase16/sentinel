from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class GitMeta:
    commit: Optional[str]
    timestamp: Optional[int]


@dataclass
class Evidence:
    path: str
    is_dir: bool
    size_bytes: int
    mtime: float
    git: GitMeta
    git_deleted_previously: bool
    references: List[str]
    type: str

    def to_json(self) -> dict:
        payload = asdict(self)
        payload["git"] = {"commit": self.git.commit, "timestamp": self.git.timestamp}
        return payload


@dataclass
class DispositionRecord:
    path: str
    disposition: str
    confidence: float
    rationale: str
    questions: List[str]
    evidence: Evidence

    def to_json(self) -> dict:
        payload = {
            "path": self.path,
            "disposition": self.disposition,
            "confidence": round(self.confidence, 2),
            "rationale": self.rationale,
            "questions": self.questions,
            "evidence": self.evidence.to_json(),
        }
        return payload


ROOT = Path(__file__).resolve().parents[2]
SKIP_GIT = {".git"}
AGGREGATE_DIRS = {
    ".venv": "build",
    "venv": "build",
    ".pytest_cache": "test",
    "__pycache__": "build",
    ".swiftpm": "build",
    ".build": "build",
}
PROTECTED_ROOTS = {
    "core",
    "ui",
    "docs",
    "tests",
    "tools",
    "models",
    ".github",
    "requirements.txt",
    "README.md",
    "AGENTS.md",
}
REPORTS = {
    "deletion": "deletion_list.json",
    "partial": "partial_confidence.json",
    "archive": "archive_manifest.json",
}


def run_git(args: List[str]) -> Optional[str]:
    try:
        output = subprocess.check_output(["git", *args], cwd=ROOT, stderr=subprocess.DEVNULL)
        return output.decode().strip() or None
    except Exception:
        return None


def git_last_commit(rel_path: Path) -> GitMeta:
    path_str = str(rel_path)
    if not run_git(["ls-files", "--error-unmatch", path_str]):
        return GitMeta(commit=None, timestamp=None)
    meta = run_git(["log", "-1", "--format=%H|%ct", "--", path_str])
    if not meta or "|" not in meta:
        return GitMeta(commit=None, timestamp=None)
    commit, ts = meta.split("|", 1)
    try:
        return GitMeta(commit=commit, timestamp=int(ts))
    except ValueError:
        return GitMeta(commit=commit, timestamp=None)


def git_deleted_previously(rel_path: Path) -> bool:
    path_str = str(rel_path)
    if not run_git(["ls-files", "--error-unmatch", path_str]):
        return False
    deleted = run_git(["log", "--diff-filter=D", "-n", "1", "--format=%H", "--", path_str])
    return bool(deleted)


def dir_size(path: Path) -> int:
    total = 0
    for root, dirs, files in os.walk(path):
        for f in files:
            try:
                total += (Path(root) / f).stat().st_size
            except FileNotFoundError:
                continue
    return total


def classify(path: Path, is_dir: bool) -> str:
    parts = path.parts
    if "models" in parts:
        return "model"
    if "tests" in parts or path.suffix in {".py", ".swift"} and "test" in path.stem.lower():
        return "test"
    if "assets" in parts or path.suffix in {".wordlist", ".dict"}:
        return "asset"
    if path.suffix in {".md", ".markdown", ".txt", ".rst", ".html"}:
        return "doc"
    if path.suffix in {".yml", ".yaml", ".json", ".toml", ".lock"}:
        return "build"
    if path.suffix in {".sh", ".ps1"}:
        return "build"
    if is_dir and path.name in {".swiftpm", ".build"}:
        return "build"
    if path.suffix in {".py", ".swift", ".rs", ".go", ".ts", ".js"}:
        return "code"
    return "doc" if path.suffix else "asset"


def inventory() -> List[Evidence]:
    records: List[Evidence] = []
    for root, dirs, files in os.walk(ROOT):
        root_path = Path(root)
        dirs[:] = [d for d in dirs if d not in SKIP_GIT]
        aggregated = []
        for d in list(dirs):
            if d in AGGREGATE_DIRS:
                target = root_path / d
                size_bytes = dir_size(target)
                mtime = target.stat().st_mtime
                rel = target.relative_to(ROOT)
                records.append(
                    Evidence(
                        path=str(rel),
                        is_dir=True,
                        size_bytes=size_bytes,
                        mtime=mtime,
                        git=git_last_commit(rel),
                        git_deleted_previously=git_deleted_previously(rel),
                        references=[],
                        type=AGGREGATE_DIRS[d],
                    )
                )
                aggregated.append(d)
        dirs[:] = [d for d in dirs if d not in aggregated]
        for f in files:
            target = root_path / f
            rel = target.relative_to(ROOT)
            try:
                stat = target.stat()
            except FileNotFoundError:
                continue
            records.append(
                Evidence(
                    path=str(rel),
                    is_dir=False,
                    size_bytes=stat.st_size,
                    mtime=stat.st_mtime,
                    git=git_last_commit(rel),
                    git_deleted_previously=git_deleted_previously(rel),
                    references=[],
                    type=classify(rel, False),
                )
            )
    return records


def write_inventory(records: List[Evidence]) -> Path:
    dest_dir = ROOT / "archive_stage"
    dest_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": int(time.time()),
        "root": str(ROOT),
        "count": len(records),
        "records": [r.to_json() for r in records],
    }
    dest = dest_dir / "inventory.json"
    tmp = dest.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2))
    tmp.replace(dest)
    return dest


def score(record: Evidence) -> Tuple[str, float, str, List[str]]:
    path = record.path
    p = Path(path)
    parts = p.parts
    head = parts[0] if parts else ""
    suffix = p.suffix.lower()
    now = time.time()
    age_days = (now - record.mtime) / 86400 if record.mtime else 0
    questions: List[str] = []
    if head in PROTECTED_ROOTS:
        return "keep", 0.3, "protected_root", []
    if "archive_stage" in parts:
        if p.name in {REPORTS["deletion"], REPORTS["partial"], REPORTS["archive"]}:
            return "keep", 0.5, "report_artifact", []
        return "delete", 0.95, "temp_workspace", []
    if record.is_dir and head in AGGREGATE_DIRS:
        return "delete", 0.99, "generated_env_or_cache", []
    if p.name in {"__pycache__", ".mypy_cache", ".ruff_cache", ".pytest_cache"}:
        return "delete", 0.97, "tool_cache", []
    if suffix in {".pyc", ".pyo"}:
        return "delete", 0.97, "compiled_artifact", []
    if p.name in {".DS_Store", "CACHEDIR.TAG"}:
        return "delete", 0.99, "workspace_artifact", []
    if suffix == ".log" or p.name in {"server.log", "ollama.log", "conflict.log"}:
        return "delete", 0.95, "log_artifact", []
    if record.type == "build" and record.is_dir:
        return "delete", 0.95, "build_cache_dir", []
    if record.type == "test" and record.is_dir:
        return "delete", 0.95, "test_cache_dir", []
    if p.name in {".idea", ".vscode"}:
        return "delete", 0.9, "ide_artifact", []
    if record.type == "doc" and path.startswith("docs/archive/"):
        return "archive", 0.9, "archived_doc", []
    if record.type == "doc" and suffix == ".md":
        questions.append("Is this doc superseded by a newer file in the same area?")
        questions.append("Does this doc still track unfinished items?")
        if age_days > 180:
            questions.append("Doc is stale (>180d); still relevant?")
        return "unknown", 0.5, "doc_requires_review", questions
    if record.type == "code" and record.git.commit is None:
        questions.append("Is this code path intentionally untracked or experimental?")
        return "unknown", 0.4, "untracked_code", questions
    if record.type == "asset" and record.size_bytes > 50_000_000 and "models" not in parts and "assets" not in parts:
        questions.append("Is this large asset (>50MB) still required for runtime or tests?")
        return "unknown", 0.4, "large_asset", questions
    if suffix in {".zip", ".tar", ".tar.gz", ".tgz"} and record.size_bytes > 100_000_000:
        questions.append("Is this large archive needed or a leftover?")
        return "unknown", 0.4, "large_archive", questions
    if record.git.commit is None and age_days > 30:
        questions.append("Untracked and older than 30d; can it be removed?")
        return "unknown", 0.4, "untracked_stale", questions
    return "keep", 0.3, "default_keep", []


def disposition(records: List[Evidence]) -> Dict[str, List[DispositionRecord]]:
    buckets: Dict[str, List[DispositionRecord]] = {"deletion": [], "partial": [], "archive": []}
    for rec in records:
        disp, conf, rationale, questions = score(rec)
        record = DispositionRecord(
            path=rec.path,
            disposition=disp,
            confidence=conf,
            rationale=rationale,
            questions=questions,
            evidence=rec,
        )
        if disp == "delete" and conf >= 0.9 and not questions:
            buckets["deletion"].append(record)
        elif disp == "archive" and rec.type == "doc" and not questions:
            buckets["archive"].append(record)
        else:
            buckets["partial"].append(record)
    return buckets


def lint_structure_check() -> Tuple[bool, str]:
    try:
        proc = subprocess.run(
            [sys.executable, "tools/lint_structure.py"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        ok = proc.returncode == 0 and "Unexpected item" not in output
        return ok, output.strip()
    except Exception as exc:
        return False, f"lint_structure_error:{exc}"


def simulate_safety(buckets: Dict[str, List[DispositionRecord]]) -> Dict[str, List[DispositionRecord]]:
    kept: List[DispositionRecord] = []
    demoted: List[DispositionRecord] = []
    for rec in buckets["deletion"]:
        tracked = run_git(["ls-files", "--error-unmatch", rec.path]) is not None
        if tracked:
            rec.rationale = "tracked_in_git"
            rec.confidence = 0.6
            rec.questions = ["This file is tracked in git; is it superseded or safe to remove?"]
            demoted.append(rec)
        else:
            kept.append(rec)
    buckets["deletion"] = kept
    buckets["partial"].extend(demoted)
    lint_ok, lint_output = lint_structure_check()
    if not lint_ok:
        now = time.time()
        ev = Evidence(
            path=".",
            is_dir=True,
            size_bytes=0,
            mtime=now,
            git=GitMeta(commit=None, timestamp=None),
            git_deleted_previously=False,
            references=[],
            type="build",
        )
        buckets["partial"].append(
            DispositionRecord(
                path="STRUCTURE_CHECK",
                disposition="keep",
                confidence=0.1,
                rationale=f"lint_structure_warn:{lint_output}",
                questions=["Investigate lint_structure warnings before deletion."],
                evidence=ev,
            )
        )
    return buckets


def validate_reports(buckets: Dict[str, List[DispositionRecord]]) -> None:
    for rec in buckets["deletion"]:
        assert rec.confidence >= 0.9
        assert not rec.questions
        assert rec.disposition == "delete"
    for rec in buckets["archive"]:
        assert rec.evidence.type == "doc"
        assert rec.disposition == "archive"
        assert not rec.questions
    for rec in buckets["partial"]:
        assert rec.disposition in {rec.disposition, "unknown", "keep", "archive", "delete"}


def write_reports(buckets: Dict[str, List[DispositionRecord]]) -> Dict[str, Path]:
    dest_dir = ROOT / "archive_stage"
    dest_dir.mkdir(parents=True, exist_ok=True)
    paths: Dict[str, Path] = {}
    for key, fname in REPORTS.items():
        dest = dest_dir / fname
        tmp = dest.with_suffix(".json.tmp")
        payload = [r.to_json() for r in buckets[key]]
        tmp.write_text(json.dumps(payload, indent=2))
        tmp.replace(dest)
        paths[key] = dest
    return paths


def run_scan() -> Dict[str, Path]:
    records = inventory()
    write_inventory(records)
    buckets = disposition(records)
    buckets = simulate_safety(buckets)
    validate_reports(buckets)
    return write_reports(buckets)


def read_json(path: Optional[Path], default) -> object:
    if not path:
        return default
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["scan"], required=True)
    args = parser.parse_args(argv)
    if args.mode == "scan":
        paths = run_scan()
        total = 0
        for key in ("deletion", "partial", "archive"):
            total += len(read_json(paths.get(key), []))
        print("reports=", ",".join(f"{k}:{v}" for k, v in paths.items()), "records=", total)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
