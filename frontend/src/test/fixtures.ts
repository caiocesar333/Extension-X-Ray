import type { AnalysisReport } from '../types'

export const reportFixture: AnalysisReport = {
  schema_version: '1.0.0', analysis_kind: 'extension', report_id: 'test', generated_at: '2026-11-17T00:00:00Z', source_filename: 'fixture.vsix', sha256: 'a'.repeat(64),
  extension: { name: 'fixture', publisher: 'xray', version: '1.0.0', display_name: 'Fixture Extension', description: 'Test fixture', activation_events: ['onCommand:xray.test'], main: './index.js', browser: null, commands: [], dependencies: {}, dev_dependencies: {}, engines: { vscode: '^1.90.0' }, categories: [], repository: null, package_path: 'extension/package.json' },
  archive: { compressed_bytes: 100, uncompressed_bytes: 200, file_count: 2, compression_ratio: 2 },
  severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
  findings: [{ id: 'one', rule_id: 'EXR-PROC-001', title: 'Process execution API', severity: 'high', confidence: 'high', description: 'Process call.', evidence: { summary: 'Matched', snippet: "cp.exec('demo')" }, location: { file: 'extension/index.js', line: 4, column: 2 }, potential_impact: 'Could start a process.', guidance: 'Trace arguments.', tags: ['process'], source: 'native' }],
  files: [{ path: 'extension/package.json', size: 100, compressed_size: 50, sha256: 'b'.repeat(64), kind: 'json' }, { path: 'extension/index.js', size: 100, compressed_size: 50, sha256: 'c'.repeat(64), kind: 'javascript' }],
  modules: { nodes: [{ id: 'one', label: 'index.js', path: 'extension/index.js', kind: 'source' }], edges: [], source: 'native' },
  rea: { available: true, used: false, status: 'fallback', version: '6.7.0', message: 'Native fallback active.', evidence_id: null, analyzed_files: 0 },
  limitations: ['Static analysis cannot prove runtime reachability.'],
}

export const repositoryReportFixture: AnalysisReport = {
  schema_version: '1.1.0', analysis_kind: 'repository', report_id: 'repo-test', generated_at: '2026-11-20T00:00:00Z', source_filename: 'repository.zip', sha256: 'd'.repeat(64),
  repository: { name: 'repository-fixture', version: '2.0.0', description: 'Repository fixture', ecosystems: ['javascript'], manifests: ['package.json'], package_manager: 'npm', scripts: { test: 'vitest' }, dependency_count: 3, workflow_count: 1, security_config_files: ['.github/workflows/test.yml'] },
  sbom: { $schema: 'http://cyclonedx.org/schema/bom-1.6.schema.json', bomFormat: 'CycloneDX', specVersion: '1.6', serialNumber: 'urn:uuid:00000000-0000-4000-8000-000000000000', version: 1, components: [{ type: 'library', 'bom-ref': 'pkg:npm/elliptic@6.5.3', name: 'elliptic', version: '6.5.3', purl: 'pkg:npm/elliptic@6.5.3', scope: 'required', hashes: [], properties: [] }] },
  supply_chain: { component_count: 1, direct_dependency_count: 1, lockfile: { path: 'package-lock.json', lockfile_version: 3, package_count: 1, integrity_count: 0, missing_integrity_count: 1, external_source_count: 0, install_script_count: 0 }, advisory_database: { available: true, source: 'OSV', snapshot_date: '2026-11-21', coverage: 'Curated fixture', record_count: 1, message: 'Offline snapshot loaded.' }, advisory_matches: [{ advisory_id: 'GHSA-r9p9-mrjm-926w', aliases: ['CVE-2020-28498'], package: 'elliptic', version: '6.5.3', severity: 'medium', summary: 'Synthetic advisory match', fixed_version: '6.5.4', reference: 'https://osv.dev/vulnerability/GHSA-r9p9-mrjm-926w' }] },
  archive: { compressed_bytes: 100, uncompressed_bytes: 200, file_count: 2, compression_ratio: 2 },
  severity_counts: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
  findings: [{ id: 'repo-one', rule_id: 'CRYPTO-TX-001', title: 'Potential wallet data exfiltration chain', severity: 'critical', confidence: 'high', description: 'Correlated wallet and network access.', evidence: { summary: 'Correlated', snippet: "fetch('https://example.invalid')" }, location: { file: 'src/index.js', line: 8, column: 2 }, potential_impact: 'Wallet data could leave the host.', guidance: 'Trace the data flow.', tags: ['crypto'], source: 'repository-native' }],
  files: [{ path: 'package.json', size: 100, compressed_size: 50, sha256: 'e'.repeat(64), kind: 'json' }],
  modules: { nodes: [], edges: [], source: 'native' },
  rea: { available: true, used: true, status: 'completed', version: '6.7.0', message: 'REA completed.', evidence_id: 'ev_test', analyzed_files: 2 },
  limitations: ['Static analysis only.'],
}

