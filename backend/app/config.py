from __future__ import annotations

import os
from dataclasses import dataclass


def _positive_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    parsed = int(value)
    if parsed <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return parsed


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    max_upload_bytes: int = 25 * 1024 * 1024
    max_entries: int = 5_000
    max_file_bytes: int = 15 * 1024 * 1024
    max_total_uncompressed_bytes: int = 100 * 1024 * 1024
    max_compression_ratio: float = 200.0
    max_metadata_bytes: int = 2 * 1024 * 1024

    @classmethod
    def from_env(cls) -> "ArchiveLimits":
        defaults = cls()
        return cls(
            max_upload_bytes=_positive_int("XRAY_MAX_UPLOAD_BYTES", defaults.max_upload_bytes),
            max_entries=_positive_int("XRAY_MAX_ENTRIES", defaults.max_entries),
            max_file_bytes=_positive_int("XRAY_MAX_FILE_BYTES", defaults.max_file_bytes),
            max_total_uncompressed_bytes=_positive_int(
                "XRAY_MAX_UNCOMPRESSED_BYTES", defaults.max_total_uncompressed_bytes
            ),
            max_compression_ratio=float(
                os.getenv("XRAY_MAX_COMPRESSION_RATIO", str(defaults.max_compression_ratio))
            ),
            max_metadata_bytes=_positive_int(
                "XRAY_MAX_METADATA_BYTES", defaults.max_metadata_bytes
            ),
        )


@dataclass(frozen=True, slots=True)
class ReaSettings:
    mode: str = "auto"
    command: str = "rea"
    timeout_seconds: float = 15.0
    max_source_files: int = 150

    @classmethod
    def from_env(cls) -> "ReaSettings":
        mode = os.getenv("XRAY_REA_MODE", "auto").lower()
        if mode not in {"auto", "disabled", "required"}:
            raise ValueError("XRAY_REA_MODE must be auto, disabled, or required")
        return cls(
            mode=mode,
            command=os.getenv("XRAY_REA_COMMAND", "rea"),
            timeout_seconds=float(os.getenv("XRAY_REA_TIMEOUT_SECONDS", "15")),
            max_source_files=_positive_int("XRAY_REA_MAX_SOURCE_FILES", 150),
        )

