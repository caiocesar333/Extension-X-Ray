from __future__ import annotations

import io
import stat
import zipfile
from pathlib import Path

import pytest

from app.archive import SafeVsixInspector
from app.config import ArchiveLimits
from app.errors import UnsafeArchiveError

from conftest import build_vsix, manifest


def test_extracts_valid_vsix_and_hashes_files(benign_vsix: Path, tmp_path: Path) -> None:
    result = SafeVsixInspector().extract(benign_vsix, tmp_path / "out")

    assert len(result.sha256) == 64
    assert result.archive.file_count == 4
    assert any(item.path == "extension/package.json" for item in result.files)
    assert all(len(item.sha256) == 64 for item in result.files)


@pytest.mark.parametrize(
    "unsafe_name",
    [
        "../escape.js",
        "/absolute.js",
        "C:\\escape.js",
        "extension/../../x",
        "extension/source.js:payload",
        "extension/NUL.txt",
        "extension/trailing. ",
    ],
)
def test_rejects_path_traversal(unsafe_name: str, tmp_path: Path) -> None:
    path = tmp_path / "unsafe.vsix"
    path.write_bytes(build_vsix({"extension/package.json": manifest(), unsafe_name: "no-op"}))

    with pytest.raises(UnsafeArchiveError, match="path") as error:
        SafeVsixInspector().extract(path, tmp_path / "out")
    assert error.value.code == "unsafe_path"


def test_rejects_symbolic_links(tmp_path: Path) -> None:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("extension/package.json", manifest())
        link = zipfile.ZipInfo("extension/link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "target")
    path = tmp_path / "link.vsix"
    path.write_bytes(output.getvalue())

    with pytest.raises(UnsafeArchiveError) as error:
        SafeVsixInspector().extract(path, tmp_path / "out")
    assert error.value.code == "symbolic_link"


def test_rejects_suspicious_compression_ratio(tmp_path: Path) -> None:
    path = tmp_path / "bomb.vsix"
    path.write_bytes(
        build_vsix(
            {
                "extension/package.json": manifest(),
                "extension/padding.txt": "0" * (128 * 1024),
            }
        )
    )
    limits = ArchiveLimits(max_compression_ratio=5.0)

    with pytest.raises(UnsafeArchiveError) as error:
        SafeVsixInspector(limits).extract(path, tmp_path / "out")
    assert error.value.code == "suspicious_compression_ratio"


def test_rejects_malformed_vsix(tmp_path: Path) -> None:
    path = tmp_path / "bad.vsix"
    path.write_bytes(b"not a zip")

    with pytest.raises(UnsafeArchiveError) as error:
        SafeVsixInspector().extract(path, tmp_path / "out")
    assert error.value.code == "malformed_vsix"

