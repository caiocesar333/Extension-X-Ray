from __future__ import annotations

import hashlib
import os
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .config import ArchiveLimits
from .errors import UnsafeArchiveError
from .models import ArchiveSummary, FileEntry

_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_WINDOWS_RESERVED = re.compile(r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$", re.IGNORECASE)
_ALLOWED_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
_CHUNK_SIZE = 128 * 1024


@dataclass(frozen=True, slots=True)
class ExtractedVsix:
    sha256: str
    files: list[FileEntry]
    archive: ArchiveSummary


def _kind_for(path: str) -> str:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in {".js", ".mjs", ".cjs", ".jsx"}:
        return "javascript"
    if suffix in {".ts", ".mts", ".cts", ".tsx"}:
        return "typescript"
    if suffix in {".json", ".jsonc"}:
        return "json"
    if suffix in {".md", ".txt", ".html", ".css", ".svg"}:
        return "text"
    if suffix in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico"}:
        return "image"
    if suffix in {".node", ".dll", ".so", ".dylib", ".exe"}:
        return "native"
    return "other"


def _safe_member_path(name: str) -> str:
    if not name or "\x00" in name:
        raise UnsafeArchiveError("unsafe_path", "Archive contains an empty or NUL path")
    candidate = name.replace("\\", "/")
    if candidate.startswith(("/", "//")) or _WINDOWS_DRIVE.match(candidate):
        raise UnsafeArchiveError("unsafe_path", f"Archive path is absolute: {name!r}")
    parts = PurePosixPath(candidate).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise UnsafeArchiveError("unsafe_path", f"Archive path is not safe: {name!r}")
    if any(
        ":" in part
        or part.endswith((" ", "."))
        or _WINDOWS_RESERVED.fullmatch(part) is not None
        for part in parts
    ):
        raise UnsafeArchiveError(
            "unsafe_path",
            f"Archive path uses a reserved or ambiguous filesystem name: {name!r}",
        )
    normalized = "/".join(parts)
    if len(normalized) > 512:
        raise UnsafeArchiveError("unsafe_path", "Archive contains an excessively long path")
    return normalized


def _validate_entry_type(info: zipfile.ZipInfo) -> None:
    if info.flag_bits & 0x1:
        raise UnsafeArchiveError("encrypted_entry", "Encrypted archive entries are not supported")
    if info.compress_type not in _ALLOWED_COMPRESSION:
        raise UnsafeArchiveError(
            "unsupported_compression",
            f"Unsupported compression method for {info.filename!r}",
        )
    mode = (info.external_attr >> 16) & 0xFFFF
    file_type = stat.S_IFMT(mode)
    if file_type == stat.S_IFLNK:
        raise UnsafeArchiveError("symbolic_link", f"Symbolic links are forbidden: {info.filename!r}")
    if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
        raise UnsafeArchiveError("special_entry", f"Special archive entry is forbidden: {info.filename!r}")


def _archive_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


class SafeVsixInspector:
    def __init__(self, limits: ArchiveLimits | None = None) -> None:
        self.limits = limits or ArchiveLimits.from_env()

    def extract(self, archive_path: Path, destination: Path) -> ExtractedVsix:
        compressed_bytes = archive_path.stat().st_size
        if compressed_bytes > self.limits.max_upload_bytes:
            raise UnsafeArchiveError("upload_too_large", "VSIX exceeds the upload size limit")
        if not zipfile.is_zipfile(archive_path):
            raise UnsafeArchiveError("malformed_vsix", "The uploaded file is not a valid ZIP/VSIX archive")

        destination.mkdir(parents=True, exist_ok=False)
        destination_root = destination.resolve()
        files: list[FileEntry] = []
        total_declared = 0
        total_actual = 0
        seen_paths: set[str] = set()

        try:
            with zipfile.ZipFile(archive_path) as archive:
                entries = archive.infolist()
                if len(entries) > self.limits.max_entries:
                    raise UnsafeArchiveError("too_many_entries", "VSIX contains too many archive entries")
                for info in entries:
                    _validate_entry_type(info)
                    safe_path = _safe_member_path(info.filename)
                    identity = safe_path.casefold()
                    if identity in seen_paths:
                        raise UnsafeArchiveError(
                            "duplicate_path",
                            f"VSIX contains a duplicate or case-colliding path: {safe_path!r}",
                        )
                    seen_paths.add(identity)

                    is_directory = info.is_dir() or info.filename.endswith(("/", "\\"))
                    if is_directory:
                        target = destination.joinpath(*PurePosixPath(safe_path).parts)
                        self._assert_contained(target, destination_root)
                        target.mkdir(parents=True, exist_ok=True)
                        continue

                    if info.file_size > self.limits.max_file_bytes:
                        raise UnsafeArchiveError("file_too_large", f"Archive member is too large: {safe_path!r}")
                    total_declared += info.file_size
                    if total_declared > self.limits.max_total_uncompressed_bytes:
                        raise UnsafeArchiveError(
                            "decompression_limit",
                            "VSIX exceeds the total decompression limit",
                        )
                    ratio = info.file_size / max(info.compress_size, 1)
                    if info.file_size >= 64 * 1024 and ratio > self.limits.max_compression_ratio:
                        raise UnsafeArchiveError(
                            "suspicious_compression_ratio",
                            f"Possible ZIP bomb detected in {safe_path!r}",
                        )

                    target = destination.joinpath(*PurePosixPath(safe_path).parts)
                    self._assert_contained(target, destination_root)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    digest = hashlib.sha256()
                    member_size = 0
                    with archive.open(info, "r") as source, target.open("xb") as output:
                        while chunk := source.read(_CHUNK_SIZE):
                            member_size += len(chunk)
                            total_actual += len(chunk)
                            if member_size > self.limits.max_file_bytes:
                                raise UnsafeArchiveError(
                                    "file_too_large", f"Expanded archive member is too large: {safe_path!r}"
                                )
                            if total_actual > self.limits.max_total_uncompressed_bytes:
                                raise UnsafeArchiveError(
                                    "decompression_limit", "VSIX exceeded the decompression limit while reading"
                                )
                            digest.update(chunk)
                            output.write(chunk)
                    if member_size != info.file_size:
                        raise UnsafeArchiveError(
                            "size_mismatch", f"Archive member size changed while reading: {safe_path!r}"
                        )
                    files.append(
                        FileEntry(
                            path=safe_path,
                            size=member_size,
                            compressed_size=info.compress_size,
                            sha256=digest.hexdigest(),
                            kind=_kind_for(safe_path),
                        )
                    )
        except (zipfile.BadZipFile, RuntimeError, EOFError) as exc:
            raise UnsafeArchiveError("malformed_vsix", "The VSIX archive could not be read safely") from exc
        except OSError as exc:
            raise UnsafeArchiveError("archive_io_error", "The VSIX archive could not be extracted") from exc

        if not files:
            raise UnsafeArchiveError("empty_archive", "The VSIX archive contains no files")
        files.sort(key=lambda entry: entry.path.casefold())
        ratio = total_actual / max(compressed_bytes, 1)
        return ExtractedVsix(
            sha256=_archive_sha256(archive_path),
            files=files,
            archive=ArchiveSummary(
                compressed_bytes=compressed_bytes,
                uncompressed_bytes=total_actual,
                file_count=len(files),
                compression_ratio=round(ratio, 2),
            ),
        )

    @staticmethod
    def _assert_contained(target: Path, destination_root: Path) -> None:
        resolved = target.resolve()
        try:
            common = os.path.commonpath((str(destination_root), str(resolved)))
        except ValueError as exc:
            raise UnsafeArchiveError("unsafe_path", "Archive member escapes extraction root") from exc
        if os.path.normcase(common) != os.path.normcase(str(destination_root)):
            raise UnsafeArchiveError("unsafe_path", "Archive member escapes extraction root")

