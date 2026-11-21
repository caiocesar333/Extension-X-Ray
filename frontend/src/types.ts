export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Confidence = 'high' | 'medium' | 'low'
export type ScanKind = 'extension' | 'repository'

export interface Finding {
  id: string
  rule_id: string
  title: string
  severity: Severity
  confidence: Confidence
  description: string
  evidence: { summary: string; snippet: string | null }
  location: { file: string; line: number | null; column: number | null } | null
  potential_impact: string
  guidance: string
  tags: string[]
  source: string
}

export interface FileEntry {
  path: string
  size: number
  compressed_size: number
  sha256: string
  kind: string
}

export interface ModuleGraph {
  nodes: Array<{ id: string; label: string; path: string | null; kind: string }>
  edges: Array<{ source: string; target: string; specifier: string }>
  source: string
}

export interface CycloneDxComponent {
  type: 'library'
  'bom-ref': string
  group?: string
  name: string
  version: string
  purl: string
  scope: 'required' | 'optional' | 'excluded'
  hashes: Array<{ alg: 'SHA-256' | 'SHA-384' | 'SHA-512'; content: string }>
  properties: Array<{ name: string; value: string }>
}

export interface CycloneDxBom {
  $schema: string
  bomFormat: 'CycloneDX'
  specVersion: '1.6'
  serialNumber: string
  version: number
  components: CycloneDxComponent[]
}

export interface SupplyChainSummary {
  component_count: number
  direct_dependency_count: number
  lockfile: {
    path: string | null
    lockfile_version: number | null
    package_count: number
    integrity_count: number
    missing_integrity_count: number
    external_source_count: number
    install_script_count: number
  }
  advisory_database: {
    available: boolean
    source: string | null
    snapshot_date: string | null
    coverage: string | null
    record_count: number
    message: string
  }
  advisory_matches: Array<{
    advisory_id: string
    aliases: string[]
    package: string
    version: string
    severity: Severity
    summary: string
    fixed_version: string | null
    reference: string | null
  }>
}

interface BaseAnalysisReport {
  report_id: string
  generated_at: string
  source_filename: string
  sha256: string
  archive: { compressed_bytes: number; uncompressed_bytes: number; file_count: number; compression_ratio: number }
  severity_counts: Record<Severity, number>
  findings: Finding[]
  files: FileEntry[]
  modules: ModuleGraph
  rea: { available: boolean; used: boolean; status: string; version: string | null; message: string; evidence_id: string | null; analyzed_files: number }
  limitations: string[]
}

export interface ExtensionAnalysisReport extends BaseAnalysisReport {
  schema_version: '1.0.0'
  analysis_kind: 'extension'
  extension: {
    name: string
    publisher: string
    version: string
    display_name: string | null
    description: string | null
    activation_events: string[]
    main: string | null
    browser: string | null
    commands: Array<{ command: string; title: string | null; category: string | null }>
    dependencies: Record<string, string>
    dev_dependencies: Record<string, string>
    engines: Record<string, string>
    categories: string[]
    repository: string | null
    package_path: string
  }
}

export interface RepositoryAnalysisReport extends BaseAnalysisReport {
  schema_version: '1.1.0'
  analysis_kind: 'repository'
  repository: {
    name: string
    version: string | null
    description: string | null
    ecosystems: string[]
    manifests: string[]
    package_manager: string | null
    scripts: Record<string, string>
    dependency_count: number
    workflow_count: number
    security_config_files: string[]
  }
  sbom: CycloneDxBom
  supply_chain: SupplyChainSummary
}

export type AnalysisReport = ExtensionAnalysisReport | RepositoryAnalysisReport

