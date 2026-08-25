"""Focused contracts for the exact-SHA R5C9 backend runtime producer."""

from pathlib import Path

from scripts import build_r5c9_runtime_handoff as handoff


def test_runtime_requirements_drop_only_the_checkout_editable_install() -> None:
    locked = "fastapi==1.0\n-e .\nrequests==2.0\n"

    assert handoff.filter_runtime_requirements(locked) == (
        "fastapi==1.0\nrequests==2.0\n"
    )


def test_start_script_is_relative_authenticated_and_loopback_confined() -> None:
    script = handoff.render_start_script()

    assert "/Users/jason/Developer/sentinelforge" not in script
    assert 'handoff_root=$(CDPATH= cd -- "$(dirname -- "$0")/.."' in script
    assert 'export SENTINEL_API_HOST="127.0.0.1"' in script
    assert 'export SENTINEL_API_PORT="8766"' in script
    assert 'export SENTINEL_REQUIRE_AUTH="true"' in script
    assert f'export SENTINEL_BUILD_SHA="{handoff.SOURCE_COMMIT}"' in script
    assert 'export PYTHONDONTWRITEBYTECODE="1"' in script
    assert 'export PYTHONNOUSERSITE="1"' in script
    assert 'cd "$source_root"' in script
    assert 'exec "$python" -m uvicorn core.server.api:app' in script
    assert "rm -" not in script


def test_identity_script_checks_payload_without_per_file_output() -> None:
    script = handoff.render_identity_script()

    assert "shasum -a 256 --status -c PAYLOAD_FILES.sha256" in script
    assert f'= "{handoff.SOURCE_COMMIT}"' in script
    assert f'= "{handoff.SOURCE_TREE}"' in script
    assert 'test -z "$(git -C "$source_root" remote)"' in script
    assert 'test ! -e "$source_root/.git/objects/info/alternates"' in script
    assert 'test -f "$source_root/.git/shallow"' in script
    assert 'rev-list --count HEAD)" = "1"' in script
    assert 'config --bool core.symlinks)" = "false"' in script


def test_manifest_keeps_runtime_proof_narrow() -> None:
    manifest = handoff.build_manifest(
        python_version="3.12.12",
        integrity={"payload_file_count": 1},
    )

    assert manifest["source"] == {
        "commit": handoff.SOURCE_COMMIT,
        "tree": handoff.SOURCE_TREE,
        "checkout": "source",
        "shallow": True,
        "history_commit_count": 1,
        "git_remote_count": 0,
        "git_alternates": False,
        "filesystem_symlink_count": 0,
    }
    assert manifest["runtime"]["api_host"] == "127.0.0.1"
    assert manifest["runtime"]["api_port"] == 8766
    assert manifest["runtime"]["authentication_required"] is True
    assert manifest["boundaries"] == {
        "loopback_only": True,
        "contains_api_token": False,
        "runs_acceptance": False,
        "changes_lab_source": False,
        "claims_candidate_behavior": False,
    }


def test_payload_inventory_excludes_mutable_git_metadata(tmp_path: Path) -> None:
    (tmp_path / "source" / ".git").mkdir(parents=True)
    (tmp_path / "source" / ".git" / "index").write_bytes(b"mutable")
    tracked = tmp_path / "source" / "core.py"
    tracked.write_text("pass\n", encoding="utf-8")
    (tmp_path / "MANIFEST.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "PAYLOAD_FILES.sha256").write_text("", encoding="utf-8")

    assert list(handoff.iter_payload_files(tmp_path)) == [tracked]


def test_local_distribution_references_reject_editable_and_file_urls() -> None:
    freeze = "requests==2.0\n-e /tmp/project\nlocal @ file:///tmp/local\n"

    assert handoff.local_distribution_references(freeze) == [
        "-e /tmp/project",
        "local @ file:///tmp/local",
    ]


def test_symlink_inventory_rejects_external_targets(tmp_path: Path) -> None:
    (tmp_path / "external").symlink_to("/private/tmp/external")

    try:
        handoff._contained_symlinks(tmp_path)
    except handoff.BuildError as exc:
        assert "absolute symlink is not portable" in str(exc)
    else:
        raise AssertionError("absolute symlink should fail closed")
