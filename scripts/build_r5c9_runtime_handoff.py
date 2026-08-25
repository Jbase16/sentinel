#!/usr/bin/env python3
"""Build the exact-SHA isolated backend runtime required by OCB-R5 R5C9.

The resulting archive is a producer-attested sidecar for the already-built R5C9
macOS application. It contains a detached one-commit shallow Git checkout, an
isolated Python environment, and relative launch/identity helpers. It does not
run acceptance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from typing import Any, Iterable


SOURCE_COMMIT = "87057b8b0313b6aa1fe9b9036db98e040208bfc3"
SOURCE_TREE = "449902cf6095f552074ebdeefde24c2d7a17dd3f"
SCHEMA_VERSION = "sentinelforge.r5c9-runtime-handoff.v1"
ARCHIVE_BASENAME = "sentinelforge-r5c9-runtime-87057b8"
BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 8766
REQUIRED_PYTHON = (3, 12)
REQUIRED_RUNTIME_MODULES = (
    "fastapi",
    "uvicorn",
    "httpx",
    "aiosqlite",
    "websockets",
    "sse_starlette",
    "python_multipart",
    "cryptography",
    "requests",
)


class BuildError(RuntimeError):
    """Raised when the handoff cannot be produced without weakening a gate."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run_checked(
    arguments: Iterable[str | os.PathLike[str]],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    capture: bool = True,
) -> str:
    command = [os.fspath(argument) for argument in arguments]
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    return result.stdout.strip() if capture else ""


def filter_runtime_requirements(requirements: str) -> str:
    """Remove only the checkout-relative editable install from the lock file."""
    retained = []
    for line in requirements.splitlines():
        if line.strip() in {"-e .", "--editable ."}:
            continue
        retained.append(line)
    return "\n".join(retained).rstrip() + "\n"


def render_start_script() -> str:
    """Return a relocation-safe, fail-closed foreground backend launcher."""
    return f"""#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 ABSOLUTE_DATA_DIRECTORY" >&2
    exit 64
fi

case "$1" in
    /*) data_dir=$1 ;;
    *) echo "data directory must be absolute" >&2; exit 64 ;;
esac

if [ "${{SENTINEL_API_HOST:-{BACKEND_HOST}}}" != "{BACKEND_HOST}" ]; then
    echo "R5C9 runtime is confined to {BACKEND_HOST}" >&2
    exit 78
fi
if [ "${{SENTINEL_API_PORT:-{BACKEND_PORT}}}" != "{BACKEND_PORT}" ]; then
    echo "R5C9 runtime is confined to port {BACKEND_PORT}" >&2
    exit 78
fi

handoff_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
source_root="$handoff_root/source"
python="$handoff_root/python/bin/python"

mkdir -p "$data_dir/run"

export PYTHONPATH="$source_root"
export SENTINEL_DATA_DIR="$data_dir"
export SENTINEL_API_HOST="{BACKEND_HOST}"
export SENTINEL_API_PORT="{BACKEND_PORT}"
export SENTINEL_REQUIRE_AUTH="true"
export SENTINEL_BUILD_SHA="{SOURCE_COMMIT}"
export SENTINEL_BUILD_ID="r5c9-runtime-handoff"
export SENTINEL_BOOT_MANIFEST="$data_dir/run/boot_manifest.json"
export PYTHONDONTWRITEBYTECODE="1"
export PYTHONNOUSERSITE="1"

echo "R5C9 token path: $data_dir/api_token" >&2
cd "$source_root"
exec "$python" -m uvicorn core.server.api:app \
    --host "{BACKEND_HOST}" --port "{BACKEND_PORT}"
"""


def render_identity_script() -> str:
    modules = " ".join(REQUIRED_RUNTIME_MODULES)
    return f"""#!/bin/sh
set -eu

handoff_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
source_root="$handoff_root/source"
python="$handoff_root/python/bin/python"

test "$(git -C "$source_root" rev-parse HEAD)" = "{SOURCE_COMMIT}"
test "$(git -C "$source_root" show -s --format=%T HEAD)" = "{SOURCE_TREE}"
test -z "$(git -C "$source_root" status --porcelain --untracked-files=all)"
test -z "$(git -C "$source_root" remote)"
test ! -e "$source_root/.git/objects/info/alternates"
test -f "$source_root/.git/shallow"
test "$(git -C "$source_root" rev-list --count HEAD)" = "1"
test "$(git -C "$source_root" config --bool core.symlinks)" = "false"

cd "$handoff_root"
shasum -a 256 --status -c PAYLOAD_FILES.sha256

"$python" -c 'import importlib.util, sys; required = sys.argv[1:]; missing = [name for name in required if importlib.util.find_spec(name) is None]; raise SystemExit("missing modules: " + ", ".join(missing) if missing else 0)' {modules}

echo "R5C9 isolated runtime identity verified"
"""


def _make_executable(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _write_text(path: Path, content: str, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if executable:
        _make_executable(path)


def _validate_python(python: Path) -> str:
    payload = run_checked(
        [
            python,
            "-c",
            (
                "import json, platform, sys; "
                "print(json.dumps({'major': sys.version_info.major, "
                "'minor': sys.version_info.minor, 'version': platform.python_version()}))"
            ),
        ]
    )
    version = json.loads(payload)
    actual = (version["major"], version["minor"])
    if actual != REQUIRED_PYTHON:
        raise BuildError(
            f"Python {REQUIRED_PYTHON[0]}.{REQUIRED_PYTHON[1]} required; "
            f"found {version['version']}"
        )
    return str(version["version"])


def _verify_source_identity(repo_root: Path) -> None:
    commit = run_checked(
        ["git", "rev-parse", f"{SOURCE_COMMIT}^{{commit}}"], cwd=repo_root
    )
    tree = run_checked(
        ["git", "show", "-s", "--format=%T", SOURCE_COMMIT], cwd=repo_root
    )
    if commit != SOURCE_COMMIT or tree != SOURCE_TREE:
        raise BuildError(
            f"source identity mismatch: commit={commit or 'missing'} tree={tree or 'missing'}"
        )


def _create_independent_checkout(repo_root: Path, output_root: Path) -> Path:
    source_root = output_root / "source"
    branch_name = f"r5c9-runtime-source-{os.getpid()}"
    temporary_ref = f"refs/heads/{branch_name}"

    existing = subprocess.run(
        ["git", "show-ref", "--verify", "--quiet", temporary_ref],
        cwd=repo_root,
        check=False,
    )
    if existing.returncode == 0:
        raise BuildError(f"temporary source ref already exists: {temporary_ref}")

    run_checked(["git", "update-ref", temporary_ref, SOURCE_COMMIT], cwd=repo_root)
    try:
        run_checked(
            [
                "git",
                "clone",
                "--quiet",
                "--no-tags",
                "--depth",
                "1",
                "--single-branch",
                "--branch",
                branch_name,
                "--config",
                "core.symlinks=false",
                repo_root.resolve().as_uri(),
                source_root,
            ]
        )
    finally:
        run_checked(["git", "update-ref", "-d", temporary_ref], cwd=repo_root)

    run_checked(["git", "switch", "--detach", SOURCE_COMMIT], cwd=source_root)
    run_checked(["git", "branch", "-D", branch_name], cwd=source_root)
    run_checked(["git", "remote", "remove", "origin"], cwd=source_root)

    if not (source_root / ".git").is_dir():
        raise BuildError(
            "standalone source does not contain an independent .git directory"
        )
    if (source_root / ".git" / "objects" / "info" / "alternates").exists():
        raise BuildError("standalone source unexpectedly uses a Git object alternate")
    if not (source_root / ".git" / "shallow").is_file():
        raise BuildError("standalone source unexpectedly contains reachable history")
    if run_checked(["git", "rev-list", "--count", "HEAD"], cwd=source_root) != "1":
        raise BuildError(
            "standalone source contains more than the exact handoff commit"
        )
    if run_checked(["git", "remote"], cwd=source_root):
        raise BuildError("standalone source unexpectedly retains a Git remote")
    if run_checked(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=source_root
    ):
        raise BuildError("standalone source checkout is not clean")
    if (
        run_checked(["git", "config", "--bool", "core.symlinks"], cwd=source_root)
        != "false"
    ):
        raise BuildError(
            "standalone source checkout permits active filesystem symlinks"
        )
    if any(path.is_symlink() for path in source_root.rglob("*")):
        raise BuildError("standalone source unexpectedly contains an active symlink")

    _verify_source_identity(source_root)
    _write_text(
        output_root / "SOURCE_IDENTITY.json",
        json.dumps(
            {
                "commit": SOURCE_COMMIT,
                "tree": SOURCE_TREE,
                "shallow": True,
                "history_commit_count": 1,
                "git_remote_count": 0,
                "git_alternates": False,
                "filesystem_symlink_count": 0,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )
    return source_root


def local_distribution_references(freeze: str) -> list[str]:
    """Return editable or file-based distributions that break runtime isolation."""
    return [
        line
        for line in freeze.splitlines()
        if line.lstrip().startswith(("-e ", "--editable ")) or " @ file:" in line
    ]


def _install_runtime(
    builder_python: Path,
    source_root: Path,
    output_root: Path,
) -> tuple[Path, str]:
    runtime_python_root = output_root / "python"
    runtime_requirements = output_root / "requirements.runtime.txt"
    locked_requirements = (source_root / "requirements.txt").read_text(encoding="utf-8")
    _write_text(runtime_requirements, filter_runtime_requirements(locked_requirements))

    run_checked(
        [builder_python, "-m", "venv", "--copies", runtime_python_root],
        capture=False,
    )
    runtime_python = runtime_python_root / "bin" / "python"
    run_checked(
        [
            runtime_python,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--requirement",
            runtime_requirements,
        ],
        cwd=source_root,
        capture=False,
    )

    freeze = run_checked([runtime_python, "-m", "pip", "freeze", "--all"])
    local_references = local_distribution_references(freeze)
    if local_references:
        raise BuildError(
            "runtime dependency set retains local distribution references: "
            + ", ".join(local_references)
        )
    installed = output_root / "INSTALLED_DISTRIBUTIONS.txt"
    _write_text(installed, freeze.rstrip() + "\n")

    preflight_data = output_root / ".preflight-data"
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONPATH": str(source_root),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "SENTINEL_DATA_DIR": str(preflight_data),
            "SENTINEL_API_HOST": BACKEND_HOST,
            "SENTINEL_API_PORT": str(BACKEND_PORT),
            "SENTINEL_REQUIRE_AUTH": "true",
            "SENTINEL_BUILD_SHA": SOURCE_COMMIT,
            "SENTINEL_BUILD_ID": "r5c9-runtime-handoff-preflight",
        }
    )
    import_script = (
        "import importlib.util, json; "
        f"required={list(REQUIRED_RUNTIME_MODULES)!r}; "
        "missing=[name for name in required if importlib.util.find_spec(name) is None]; "
        "assert not missing, missing; import core.server.api; "
        "print(json.dumps({'required_modules': required, 'backend_import': 'ok'}))"
    )
    run_checked(
        [runtime_python, "-c", import_script],
        cwd=source_root,
        env=environment,
    )
    shutil.rmtree(preflight_data, ignore_errors=True)
    return runtime_python, freeze


def _write_runtime_helpers(output_root: Path) -> None:
    _write_text(
        output_root / "bin" / "start-backend",
        render_start_script(),
        executable=True,
    )
    _write_text(
        output_root / "bin" / "verify-identity",
        render_identity_script(),
        executable=True,
    )


def _contained_symlinks(root: Path) -> list[dict[str, str]]:
    links = []
    resolved_root = root.resolve()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            target = os.readlink(path)
            if Path(target).is_absolute():
                raise BuildError(f"absolute symlink is not portable: {path}")
            resolved_target = (path.parent / target).resolve()
            if not resolved_target.is_relative_to(resolved_root):
                raise BuildError(f"symlink escapes the handoff root: {path}")
            links.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "target": target,
                }
            )
    return links


def iter_payload_files(root: Path) -> Iterable[Path]:
    excluded_names = {"MANIFEST.json", "PAYLOAD_FILES.sha256"}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        if relative.as_posix() in excluded_names:
            continue
        if path.is_file() and not path.is_symlink():
            yield path


def _write_integrity_files(output_root: Path) -> dict[str, Any]:
    symlinks_path = output_root / "SYMLINKS.json"
    _write_text(
        symlinks_path,
        json.dumps(_contained_symlinks(output_root), indent=2, sort_keys=True) + "\n",
    )

    inventory_path = output_root / "PAYLOAD_FILES.sha256"
    entries = []
    for path in iter_payload_files(output_root):
        relative = path.relative_to(output_root).as_posix()
        entries.append(f"{sha256_file(path)}  {relative}")
    _write_text(inventory_path, "\n".join(entries) + "\n")

    return {
        "payload_file_count": len(entries),
        "payload_files_sha256": sha256_file(inventory_path),
        "symlinks_sha256": sha256_file(symlinks_path),
        "requirements_runtime_sha256": sha256_file(
            output_root / "requirements.runtime.txt"
        ),
        "installed_distributions_sha256": sha256_file(
            output_root / "INSTALLED_DISTRIBUTIONS.txt"
        ),
        "source_identity_sha256": sha256_file(output_root / "SOURCE_IDENTITY.json"),
    }


def build_manifest(*, python_version: str, integrity: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "evidence_class": "producer_attested_isolated_runtime",
        "source": {
            "commit": SOURCE_COMMIT,
            "tree": SOURCE_TREE,
            "checkout": "source",
            "shallow": True,
            "history_commit_count": 1,
            "git_remote_count": 0,
            "git_alternates": False,
            "filesystem_symlink_count": 0,
        },
        "runtime": {
            "python_version": python_version,
            "python": "python/bin/python",
            "backend_root": "source",
            "start_command": ["bin/start-backend", "ABSOLUTE_DATA_DIRECTORY"],
            "identity_command": ["bin/verify-identity"],
            "api_host": BACKEND_HOST,
            "api_port": BACKEND_PORT,
            "authentication_required": True,
            "token_path_relative_to_data_directory": "api_token",
            "fresh_state": "supply a new empty data directory for each fresh pair",
            "restart_state": "reuse that pair's data directory for its restart retry",
        },
        "integrity": integrity,
        "bound_candidate": {
            "archive_sha256": (
                "15c468936890145ce616d217ad2f0b875ad24e84d76e96bd1f2b51765f474435"
            ),
            "executable_sha256": (
                "6250ab27dc92ffdc6e2ff2186f9498473861bcd3a832994a4551ba1588d7ff35"
            ),
        },
        "boundaries": {
            "loopback_only": True,
            "contains_api_token": False,
            "runs_acceptance": False,
            "changes_lab_source": False,
            "claims_candidate_behavior": False,
        },
    }


def _write_detached_hash(path: Path) -> Path:
    detached = path.with_name(path.name + ".sha256")
    _write_text(detached, f"{sha256_file(path)}  {path.name}\n")
    return detached


def _create_archive(output_root: Path) -> Path:
    archive = output_root.parent / f"{ARCHIVE_BASENAME}.tar.gz"
    if archive.exists() or archive.with_name(archive.name + ".sha256").exists():
        raise BuildError(f"archive output already exists: {archive}")
    environment = os.environ.copy()
    environment["COPYFILE_DISABLE"] = "1"
    run_checked(
        [
            "/usr/bin/tar",
            "-czf",
            archive,
            "-C",
            output_root.parent,
            output_root.name,
        ],
        env=environment,
        capture=False,
    )
    return archive


def build(output_root: Path, builder_python: Path) -> dict[str, Any]:
    if not output_root.is_absolute():
        raise BuildError("output root must be an absolute path")
    if output_root.exists():
        raise BuildError(f"output root already exists: {output_root}")
    output_root.parent.mkdir(parents=True, exist_ok=True)

    repo_root = Path(__file__).resolve().parents[1]
    python_version = _validate_python(builder_python)
    _verify_source_identity(repo_root)

    output_root.mkdir(mode=0o755)
    source_root = _create_independent_checkout(repo_root, output_root)
    runtime_python, _ = _install_runtime(
        builder_python,
        source_root,
        output_root,
    )
    if not runtime_python.exists():
        raise BuildError("isolated runtime Python was not created")
    _write_runtime_helpers(output_root)
    integrity = _write_integrity_files(output_root)
    manifest_path = output_root / "MANIFEST.json"
    _write_text(
        manifest_path,
        json.dumps(
            build_manifest(python_version=python_version, integrity=integrity),
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )
    manifest_hash = _write_detached_hash(manifest_path)
    archive = _create_archive(output_root)
    archive_hash = _write_detached_hash(archive)

    return {
        "output_root": str(output_root),
        "archive": str(archive),
        "archive_sha256": sha256_file(archive),
        "archive_hash_file": str(archive_hash),
        "manifest": str(manifest_path),
        "manifest_sha256": sha256_file(manifest_path),
        "manifest_hash_file": str(manifest_hash),
        "payload_file_count": integrity["payload_file_count"],
        "payload_files_sha256": integrity["payload_files_sha256"],
        "source_commit": SOURCE_COMMIT,
        "source_tree": SOURCE_TREE,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-root",
        required=True,
        type=Path,
        help="new absolute directory that will contain the isolated runtime",
    )
    parser.add_argument(
        "--python",
        type=Path,
        default=Path(sys.executable),
        help="Python 3.12 interpreter used to create the isolated environment",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        summary = build(
            arguments.output_root.expanduser().resolve(),
            arguments.python.expanduser().resolve(),
        )
    except (BuildError, subprocess.CalledProcessError, OSError) as exc:
        print(f"R5C9 runtime handoff build failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
