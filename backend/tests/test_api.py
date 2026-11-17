from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.analyzer import ExtensionAnalyzer
from app.config import ReaSettings
from app.main import app
from app.rea import ReaAdapter


def client_without_rea(monkeypatch) -> TestClient:
    import app.main as main

    monkeypatch.setattr(
        main,
        "analyzer",
        ExtensionAnalyzer(rea=ReaAdapter(ReaSettings(mode="disabled"))),
    )
    return TestClient(app)


def test_analyze_endpoint_returns_report(benign_vsix: Path, monkeypatch) -> None:
    client = client_without_rea(monkeypatch)
    with benign_vsix.open("rb") as fixture:
        response = client.post(
            "/api/v1/analyze",
            files={"file": ("benign.vsix", fixture, "application/octet-stream")},
        )

    assert response.status_code == 200
    assert response.json()["extension"]["name"] == "synthetic-safe-extension"


def test_api_returns_structured_archive_error(tmp_path: Path, monkeypatch) -> None:
    client = client_without_rea(monkeypatch)
    response = client.post(
        "/api/v1/analyze",
        files={"file": ("broken.vsix", b"not a zip", "application/octet-stream")},
    )

    assert response.status_code == 422
    assert response.json() == {
        "detail": {
            "code": "malformed_vsix",
            "message": "The uploaded file is not a valid ZIP/VSIX archive",
        }
    }


def test_api_rejects_wrong_extension(monkeypatch) -> None:
    client = client_without_rea(monkeypatch)
    response = client.post(
        "/api/v1/analyze",
        files={"file": ("extension.zip", b"data", "application/zip")},
    )

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_file_type"


def test_health_and_report_schema() -> None:
    client = TestClient(app)

    assert client.get("/api/v1/health").status_code == 200
    schema = client.get("/api/v1/report-schema")
    assert schema.status_code == 200
    assert "extension" in schema.json()["properties"]

