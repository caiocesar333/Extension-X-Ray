from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


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


class AnalysisReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0.0"
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

