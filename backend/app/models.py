from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_serializer


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Confidence(StrEnum):
    high = "high"
    medium = "medium"
    low = "low"


class SourceLocation(BaseModel):
    file: str
    line: int | None = None
    column: int | None = None


class FindingEvidence(BaseModel):
    summary: str
    snippet: str | None = None


class Finding(BaseModel):
    id: str
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    description: str
    evidence: FindingEvidence
    location: SourceLocation | None = None
    potential_impact: str
    guidance: str
    tags: list[str] = Field(default_factory=list)
    source: str = "native"


class DeclaredCommand(BaseModel):
    command: str
    title: str | None = None
    category: str | None = None


class ExtensionMetadata(BaseModel):
    name: str
    publisher: str
    version: str
    display_name: str | None = None
    description: str | None = None
    activation_events: list[str] = Field(default_factory=list)
    main: str | None = None
    browser: str | None = None
    commands: list[DeclaredCommand] = Field(default_factory=list)
    dependencies: dict[str, str] = Field(default_factory=dict)
    dev_dependencies: dict[str, str] = Field(default_factory=dict)
    engines: dict[str, str] = Field(default_factory=dict)
    categories: list[str] = Field(default_factory=list)
    repository: str | None = None
    package_path: str


class RepositoryMetadata(BaseModel):
    name: str
    version: str | None = None
    description: str | None = None
    ecosystems: list[str] = Field(default_factory=list)
    manifests: list[str] = Field(default_factory=list)
    package_manager: str | None = None
    scripts: dict[str, str] = Field(default_factory=dict)
    dependency_count: int = 0
    workflow_count: int = 0
    security_config_files: list[str] = Field(default_factory=list)


class FileEntry(BaseModel):
    path: str
    size: int
    compressed_size: int
    sha256: str
    kind: str


class ArchiveSummary(BaseModel):
    compressed_bytes: int
    uncompressed_bytes: int
    file_count: int
    compression_ratio: float


class ModuleNode(BaseModel):
    id: str
    label: str
    path: str | None = None
    kind: str


class ModuleEdge(BaseModel):
    source: str
    target: str
    specifier: str


class ModuleGraph(BaseModel):
    nodes: list[ModuleNode] = Field(default_factory=list)
    edges: list[ModuleEdge] = Field(default_factory=list)
    source: str = "native"


class ReaStatus(BaseModel):
    available: bool
    used: bool
    status: str
    version: str | None = None
    message: str
    evidence_id: str | None = None
    analyzed_files: int = 0


class CycloneDxHash(BaseModel):
    alg: Literal["SHA-256", "SHA-384", "SHA-512"]
    content: str


class CycloneDxProperty(BaseModel):
    name: str
    value: str


class CycloneDxComponent(BaseModel):
    model_config = ConfigDict(populate_by_name=True, serialize_by_alias=True)

    type: Literal["library"] = "library"
    bom_ref: str = Field(alias="bom-ref")
    group: str | None = None
    name: str
    version: str
    purl: str
    scope: Literal["required", "optional", "excluded"] = "required"
    hashes: list[CycloneDxHash] = Field(default_factory=list)
    properties: list[CycloneDxProperty] = Field(default_factory=list)

    @model_serializer(mode="wrap")
    def _omit_empty_group(self, handler: Any) -> dict[str, Any]:
        data = handler(self)
        if self.group is None:
            data.pop("group", None)
        return data


class CycloneDxBom(BaseModel):
    model_config = ConfigDict(populate_by_name=True, serialize_by_alias=True)

    schema_uri: str = Field(
        default="http://cyclonedx.org/schema/bom-1.6.schema.json",
        alias="$schema",
    )
    bom_format: Literal["CycloneDX"] = Field(default="CycloneDX", alias="bomFormat")
    spec_version: Literal["1.6"] = Field(default="1.6", alias="specVersion")
    serial_number: str = Field(alias="serialNumber")
    version: int = 1
    components: list[CycloneDxComponent] = Field(default_factory=list)


class LockfileIntegritySummary(BaseModel):
    path: str | None = None
    lockfile_version: int | None = None
    package_count: int = 0
    integrity_count: int = 0
    missing_integrity_count: int = 0
    external_source_count: int = 0
    install_script_count: int = 0


class AdvisoryDatabaseStatus(BaseModel):
    available: bool
    source: str | None = None
    snapshot_date: str | None = None
    coverage: str | None = None
    record_count: int = 0
    message: str


class AdvisoryMatch(BaseModel):
    advisory_id: str
    aliases: list[str] = Field(default_factory=list)
    package: str
    version: str
    severity: Severity
    summary: str
    fixed_version: str | None = None
    reference: str | None = None


class SupplyChainSummary(BaseModel):
    component_count: int = 0
    direct_dependency_count: int = 0
    lockfile: LockfileIntegritySummary = Field(default_factory=LockfileIntegritySummary)
    advisory_database: AdvisoryDatabaseStatus
    advisory_matches: list[AdvisoryMatch] = Field(default_factory=list)


class AnalysisReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0.0"] = "1.0.0"
    analysis_kind: Literal["extension"] = "extension"
    report_id: str
    generated_at: datetime
    source_filename: str
    sha256: str
    extension: ExtensionMetadata
    archive: ArchiveSummary
    severity_counts: dict[Severity, int]
    findings: list[Finding]
    files: list[FileEntry]
    modules: ModuleGraph
    rea: ReaStatus
    limitations: list[str] = Field(default_factory=list)


class RepositoryAnalysisReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.1.0"] = "1.1.0"
    analysis_kind: Literal["repository"] = "repository"
    report_id: str
    generated_at: datetime
    source_filename: str
    sha256: str
    repository: RepositoryMetadata
    archive: ArchiveSummary
    severity_counts: dict[Severity, int]
    findings: list[Finding]
    files: list[FileEntry]
    modules: ModuleGraph
    sbom: CycloneDxBom
    supply_chain: SupplyChainSummary
    rea: ReaStatus
    limitations: list[str] = Field(default_factory=list)


class ApiErrorDetail(BaseModel):
    code: str
    message: str


class ApiError(BaseModel):
    detail: ApiErrorDetail


class HealthResponse(BaseModel):
    status: str
    version: str
    rea: ReaStatus


JsonObject = dict[str, Any]

