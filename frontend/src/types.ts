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

interface BaseAnalysisReport {
  schema_version: string
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
}

export type AnalysisReport = ExtensionAnalysisReport | RepositoryAnalysisReport

