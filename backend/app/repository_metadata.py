from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any

from .config import ArchiveLimits
from .models import FileEntry, RepositoryMetadata

_MANIFEST_ECOSYSTEMS = {
    "package.json": "javascript",
    "package-lock.json": "javascript",
    "pnpm-lock.yaml": "javascript",
    "yarn.lock": "javascript",
    "bun.lock": "javascript",
    "pyproject.toml": "python",
    "requirements.txt": "python",
    "poetry.lock": "python",
    "uv.lock": "python",
    "Cargo.toml": "rust",
    "Cargo.lock": "rust",
    "go.mod": "go",
    "go.sum": "go",
    "pom.xml": "java",
    "build.gradle": "java",
    "build.gradle.kts": "java",
    "composer.json": "php",
    "composer.lock": "php",
}

_LOCKFILE_MANAGERS = {
    "pnpm-lock.yaml": "pnpm",
    "yarn.lock": "yarn",
    "bun.lock": "bun",
    "package-lock.json": "npm",
}


def _bounded_string(value: Any, maximum: int = 4_000) -> str | None:
    return value[:maximum] if isinstance(value, str) and value else None


def _string_map(value: Any, maximum: int = 500) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {
        str(key)[:300]: item[:2_000]
        for key, item in list(value.items())[:maximum]
        if isinstance(key, str) and isinstance(item, str)
    }


def _package_candidates(files: list[FileEntry]) -> list[FileEntry]:
    return sorted(
        (
            entry
            for entry in files
            if PurePosixPath(entry.path).name == "package.json"
            and "node_modules" not in PurePosixPath(entry.path).parts
        ),
        key=lambda entry: (len(PurePosixPath(entry.path).parts), entry.path.casefold()),
    )


def _read_package(root: Path, entry: FileEntry | None, limits: ArchiveLimits) -> dict[str, Any]:
    if entry is None or entry.size > limits.max_metadata_bytes:
        return {}
    try:
        value = json.loads(root.joinpath(*entry.path.split("/")).read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def read_repository_metadata(
    root: Path,
    files: list[FileEntry],
    source_filename: str,
    limits: ArchiveLimits | None = None,
) -> RepositoryMetadata:
    active_limits = limits or ArchiveLimits.from_env()
    package_entry = next(iter(_package_candidates(files)), None)
    package = _read_package(root, package_entry, active_limits)
    file_names = {PurePosixPath(entry.path).name for entry in files}
    manifests = sorted(
        entry.path
        for entry in files
        if PurePosixPath(entry.path).name in _MANIFEST_ECOSYSTEMS
    )
    ecosystems = sorted({_MANIFEST_ECOSYSTEMS[PurePosixPath(path).name] for path in manifests})
    package_manager = next(
        (manager for filename, manager in _LOCKFILE_MANAGERS.items() if filename in file_names),
        None,
    )
    scripts = _string_map(package.get("scripts"))
    dependency_count = sum(
        len(_string_map(package.get(field), maximum=10_000))
        for field in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
    )
    workflow_count = sum(
        1
        for entry in files
        if ".github" in PurePosixPath(entry.path).parts
        and "workflows" in PurePosixPath(entry.path).parts
        and PurePosixPath(entry.path).suffix.lower() in {".yml", ".yaml"}
    )
    security_configs = sorted(
        entry.path
        for entry in files
        if any(
            marker in PurePosixPath(entry.path).parts
            for marker in (".github", ".vscode", ".devcontainer")
        )
    )
    fallback_name = Path(source_filename).stem[:500] or "repository"
    return RepositoryMetadata(
        name=_bounded_string(package.get("name"), 500) or fallback_name,
        version=_bounded_string(package.get("version"), 500),
        description=_bounded_string(package.get("description")),
        ecosystems=ecosystems,
        manifests=manifests[:2_000],
        package_manager=package_manager,
        scripts=scripts,
        dependency_count=dependency_count,
        workflow_count=workflow_count,
        security_config_files=security_configs[:2_000],
    )

