from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import ArchiveLimits
from .errors import UnsafeArchiveError
from .models import DeclaredCommand, ExtensionMetadata, FileEntry


def _short_text(value: Any, maximum: int = 4_000) -> str | None:
    return value[:maximum] if isinstance(value, str) and value else None


def _string_map(value: Any, maximum: int = 1_000) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, str] = {}
    for key, item in list(value.items())[:maximum]:
        if isinstance(key, str) and isinstance(item, str):
            result[key[:300]] = item[:1_000]
    return result


def _string_list(value: Any, maximum: int = 1_000) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item[:1_000] for item in value[:maximum] if isinstance(item, str)]


def _repository(value: Any) -> str | None:
    if isinstance(value, str):
        return value[:2_000]
    if isinstance(value, dict) and isinstance(value.get("url"), str):
        return value["url"][:2_000]
    return None


def _commands(package: dict[str, Any]) -> list[DeclaredCommand]:
    contributes = package.get("contributes")
    if not isinstance(contributes, dict) or not isinstance(contributes.get("commands"), list):
        return []
    commands: list[DeclaredCommand] = []
    for value in contributes["commands"][:1_000]:
        if not isinstance(value, dict) or not isinstance(value.get("command"), str):
            continue
        commands.append(
            DeclaredCommand(
                command=value["command"][:500],
                title=_short_text(value.get("title"), 500),
                category=_short_text(value.get("category"), 500),
            )
        )
    return commands


def read_extension_metadata(
    root: Path,
    files: list[FileEntry],
    limits: ArchiveLimits | None = None,
) -> ExtensionMetadata:
    active_limits = limits or ArchiveLimits.from_env()
    paths = {entry.path: entry for entry in files}
    candidates = [path for path in ("extension/package.json", "package.json") if path in paths]
    if not candidates:
        raise UnsafeArchiveError("missing_manifest", "VSIX does not contain extension/package.json")
    package_path = candidates[0]
    entry = paths[package_path]
    if entry.size > active_limits.max_metadata_bytes:
        raise UnsafeArchiveError("manifest_too_large", "Extension package.json exceeds the metadata limit")
    try:
        raw = root.joinpath(*package_path.split("/")).read_text(encoding="utf-8-sig")
        package = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, OSError) as exc:
        raise UnsafeArchiveError("invalid_manifest", "Extension package.json is not valid UTF-8 JSON") from exc
    if not isinstance(package, dict):
        raise UnsafeArchiveError("invalid_manifest", "Extension package.json must contain a JSON object")

    required: dict[str, str] = {}
    for key in ("name", "publisher", "version"):
        value = package.get(key)
        if not isinstance(value, str) or not value.strip():
            raise UnsafeArchiveError("invalid_manifest", f"Extension package.json is missing {key!r}")
        required[key] = value[:500]

    return ExtensionMetadata(
        name=required["name"],
        publisher=required["publisher"],
        version=required["version"],
        display_name=_short_text(package.get("displayName"), 500),
        description=_short_text(package.get("description")),
        activation_events=_string_list(package.get("activationEvents")),
        main=_short_text(package.get("main"), 1_000),
        browser=_short_text(package.get("browser"), 1_000),
        commands=_commands(package),
        dependencies=_string_map(package.get("dependencies")),
        dev_dependencies=_string_map(package.get("devDependencies")),
        engines=_string_map(package.get("engines")),
        categories=_string_list(package.get("categories"), 100),
        repository=_repository(package.get("repository")),
        package_path=package_path,
    )

