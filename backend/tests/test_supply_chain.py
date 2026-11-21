from __future__ import annotations

import json
from pathlib import Path

from app.config import ReaSettings, SupplyChainSettings
from app.rea import ReaAdapter
from app.repository_analyzer import RepositoryAnalyzer

from conftest import build_vsix


def analyzer(settings: SupplyChainSettings | None = None) -> RepositoryAnalyzer:
    return RepositoryAnalyzer(
        rea=ReaAdapter(ReaSettings(mode="disabled")),
        supply_chain_settings=settings,
    )


def test_benign_repository_emits_cyclonedx_sbom(benign_repository: Path) -> None:
    report = analyzer().analyze(benign_repository)
    document = report.model_dump(mode="json")

    assert report.schema_version == "1.1.0"
    assert report.supply_chain.component_count == 1
    assert report.supply_chain.lockfile.integrity_count == 1
    assert report.supply_chain.lockfile.missing_integrity_count == 0
    assert report.supply_chain.advisory_matches == []
    assert report.sbom.components[0].purl == "pkg:npm/kleur@4.1.5"
    assert report.sbom.components[0].hashes[0].alg == "SHA-512"
    assert document["sbom"]["bomFormat"] == "CycloneDX"
    assert document["sbom"]["specVersion"] == "1.6"
    assert document["sbom"]["serialNumber"].startswith("urn:uuid:")
    assert document["sbom"]["components"][0]["bom-ref"] == "pkg:npm/kleur@4.1.5"
    assert "group" not in document["sbom"]["components"][0]


def test_suspicious_repository_reports_supply_chain_risks(suspicious_repository: Path) -> None:
    report = analyzer().analyze(suspicious_repository)
    rules = {finding.rule_id for finding in report.findings}

    expected = {
        "SCM-ADV-001",
        "SCM-LOCK-003",
        "SCM-PROV-001",
        "SCM-NPM-001",
        "SCM-NPM-002",
        "SCM-TYPO-001",
    }
    assert expected.issubset(rules), expected - rules
    assert report.supply_chain.component_count == 3
    assert report.supply_chain.lockfile.external_source_count == 1
    assert report.supply_chain.lockfile.install_script_count == 1
    advisory = report.supply_chain.advisory_matches[0]
    assert advisory.advisory_id == "GHSA-r9p9-mrjm-926w"
    assert advisory.package == "elliptic"
    assert advisory.version == "6.5.3"
    assert advisory.fixed_version == "6.5.4"


def test_declared_dependencies_without_lockfile_are_reported(tmp_path: Path) -> None:
    archive = tmp_path / "no-lock.zip"
    archive.write_bytes(
        build_vsix(
            {
                "repo/package.json": json.dumps(
                    {
                        "name": "no-lock",
                        "version": "1.0.0",
                        "dependencies": {"kleur": "github:example/kleur#0123456789abcdef"},
                    }
                ),
                "repo/index.js": "export const value = 1;\n",
            }
        )
    )

    report = analyzer().analyze(archive)

    assert "SCM-LOCK-000" in {finding.rule_id for finding in report.findings}
    assert "SCM-NPM-002" in {finding.rule_id for finding in report.findings}
    assert report.supply_chain.component_count == 0


def test_missing_advisory_database_fails_to_explicit_offline_status(
    benign_repository: Path,
    tmp_path: Path,
) -> None:
    settings = SupplyChainSettings(advisory_database=tmp_path / "missing-osv.json")

    report = analyzer(settings).analyze(benign_repository)

    assert report.supply_chain.advisory_database.available is False
    assert "unavailable" in report.supply_chain.advisory_database.message.lower()
    assert any("advisory database unavailable" in item.lower() for item in report.limitations)


def test_github_actions_supply_chain_correlations(tmp_path: Path) -> None:
    archive = tmp_path / "workflow.zip"
    archive.write_bytes(
        build_vsix(
            {
                "repo/package.json": json.dumps({"name": "workflow-demo", "version": "1.0.0"}),
                "repo/.github/workflows/deploy.yml": """on: workflow_dispatch
permissions: write-all
jobs:
  deploy:
    permissions:
      id-token: write
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: cloud/example-action@v1
      - run: |
          synthetic-tool --token "${{ secrets.DEPLOY_TOKEN }}"
""",
            }
        )
    )

    report = analyzer().analyze(archive)
    rules = {finding.rule_id for finding in report.findings}

    assert {"SCM-CI-001", "SCM-CI-002", "SCM-CI-003"}.issubset(rules)


def test_accepts_official_osv_json_list_shape(benign_repository: Path, tmp_path: Path) -> None:
    database = tmp_path / "osv-all.json"
    database.write_text(
        json.dumps(
            [
                {
                    "schema_version": "1.7.3",
                    "id": "OSV-SYNTHETIC-0001",
                    "summary": "Synthetic non-matching record",
                    "affected": [
                        {
                            "package": {"ecosystem": "npm", "name": "not-installed"},
                            "versions": ["1.0.0"],
                        }
                    ],
                }
            ]
        ),
        encoding="utf-8",
    )

    report = analyzer(SupplyChainSettings(advisory_database=database)).analyze(benign_repository)

    status = report.supply_chain.advisory_database
    assert status.available is True
    assert status.record_count == 1
    assert status.source == "Operator-provided OSV JSON list"


def test_package_lock_v1_dependencies_are_inventoried(tmp_path: Path) -> None:
    archive = tmp_path / "v1-lock.zip"
    archive.write_bytes(
        build_vsix(
            {
                "repo/package.json": json.dumps(
                    {"name": "v1-demo", "version": "1.0.0", "dependencies": {"kleur": "4.1.5"}}
                ),
                "repo/package-lock.json": json.dumps(
                    {
                        "name": "v1-demo",
                        "version": "1.0.0",
                        "lockfileVersion": 1,
                        "dependencies": {
                            "kleur": {
                                "version": "4.1.5",
                                "resolved": "https://registry.npmjs.org/kleur/-/kleur-4.1.5.tgz"
                            }
                        }
                    }
                ),
            }
        )
    )

    report = analyzer().analyze(archive)

    assert report.supply_chain.component_count == 1
    assert report.sbom.components[0].purl == "pkg:npm/kleur@4.1.5"
    assert "SCM-LOCK-001" not in {finding.rule_id for finding in report.findings}


def test_supply_chain_evidence_redacts_registry_credentials(tmp_path: Path) -> None:
    archive = tmp_path / "credentials.zip"
    archive.write_bytes(
        build_vsix(
            {
                "repo/package.json": json.dumps(
                    {
                        "name": "credential-demo",
                        "version": "1.0.0",
                        "dependencies": {
                            "private-demo": "https://user:synthetic-password@example.invalid/package.tgz?token=synthetic-token"
                        },
                    }
                ),
                "repo/package-lock.json": json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"name": "credential-demo", "version": "1.0.0"},
                            "node_modules/private-demo": {
                                "version": "1.0.0",
                                "resolved": "https://user:synthetic-password@example.invalid/package.tgz?token=synthetic-token",
                            },
                        },
                    }
                ),
            }
        )
    )

    report = analyzer().analyze(archive)
    serialized_findings = "".join(finding.model_dump_json() for finding in report.findings)

    assert "synthetic-password" not in serialized_findings
    assert "synthetic-token" not in serialized_findings
    assert "[REDACTED]" in serialized_findings
