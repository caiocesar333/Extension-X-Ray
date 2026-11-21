from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app import __version__
from app.analyzer import ExtensionAnalyzer
from app.config import ReaSettings
from app.main import app
from app.rea import ReaAdapter
from app.repository_analyzer import RepositoryAnalyzer


def client_without_rea(monkeypatch) -> TestClient:
    import app.main as main

    monkeypatch.setattr(
        main,
        "analyzer",
        ExtensionAnalyzer(rea=ReaAdapter(ReaSettings(mode="disabled"))),
    )
    monkeypatch.setattr(
        main,
        "repository_analyzer",
        RepositoryAnalyzer(rea=ReaAdapter(ReaSettings(mode="disabled"))),
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

    health = client.get("/api/v1/health")
    assert health.status_code == 200
    assert health.json()["version"] == __version__
    schema = client.get("/api/v1/report-schema")
    assert schema.status_code == 200
    assert "extension" in schema.json()["properties"]
    assert schema.json()["properties"]["schema_version"]["const"] == "1.0.0"
    repository_schema = client.get("/api/v1/repository-report-schema")
    assert repository_schema.status_code == 200
    assert "repository" in repository_schema.json()["properties"]
    assert repository_schema.json()["properties"]["schema_version"]["const"] == "1.1.0"
    assert client.get("/openapi.json").json()["info"]["version"] == __version__


def test_analyze_repository_endpoint_returns_report(suspicious_repository: Path, monkeypatch) -> None:
    client = client_without_rea(monkeypatch)
    with suspicious_repository.open("rb") as fixture:
        response = client.post(
            "/api/v1/analyze-repository",
            files={"file": ("repository.zip", fixture, "application/zip")},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["analysis_kind"] == "repository"
    assert body["schema_version"] == "1.1.0"
    assert body["repository"]["name"] == "synthetic-crypto-stealer-patterns"
    assert body["sbom"]["bomFormat"] == "CycloneDX"
    assert body["supply_chain"]["component_count"] == 3
    assert any(item["rule_id"] == "CRYPTO-TX-001" for item in body["findings"])


def test_repository_endpoint_rejects_non_zip(monkeypatch) -> None:
    client = client_without_rea(monkeypatch)
    response = client.post(
        "/api/v1/analyze-repository",
        files={"file": ("repository.tar", b"data", "application/octet-stream")},
    )

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_file_type"


def test_repository_endpoint_uses_repository_specific_archive_error(monkeypatch) -> None:
    client = client_without_rea(monkeypatch)
    response = client.post(
        "/api/v1/analyze-repository",
        files={"file": ("repository.zip", b"not a zip", "application/zip")},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == {
        "code": "malformed_repository",
        "message": "The uploaded file is not a valid repository ZIP archive",
    }

