import type { AnalysisReport } from '../types'

export const reportFixture: AnalysisReport = {
  schema_version: '1.0.0', report_id: 'test', generated_at: '2026-11-17T00:00:00Z', source_filename: 'fixture.vsix', sha256: 'a'.repeat(64),
  extension: { name: 'fixture', publisher: 'xray', version: '1.0.0', display_name: 'Fixture Extension', description: 'Test fixture', activation_events: ['onCommand:xray.test'], main: './index.js', browser: null, commands: [], dependencies: {}, dev_dependencies: {}, engines: { vscode: '^1.90.0' }, categories: [], repository: null, package_path: 'extension/package.json' },
  archive: { compressed_bytes: 100, uncompressed_bytes: 200, file_count: 2, compression_ratio: 2 },
  severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
  findings: [{ id: 'one', rule_id: 'EXR-PROC-001', title: 'Process execution API', severity: 'high', confidence: 'high', description: 'Process call.', evidence: { summary: 'Matched', snippet: "cp.exec('demo')" }, location: { file: 'extension/index.js', line: 4, column: 2 }, potential_impact: 'Could start a process.', guidance: 'Trace arguments.', tags: ['process'], source: 'native' }],
  files: [{ path: 'extension/package.json', size: 100, compressed_size: 50, sha256: 'b'.repeat(64), kind: 'json' }, { path: 'extension/index.js', size: 100, compressed_size: 50, sha256: 'c'.repeat(64), kind: 'javascript' }],
  modules: { nodes: [{ id: 'one', label: 'index.js', path: 'extension/index.js', kind: 'source' }], edges: [], source: 'native' },
  rea: { available: true, used: false, status: 'fallback', version: '6.7.0', message: 'Native fallback active.', evidence_id: null, analyzed_files: 0 },
  limitations: ['Static analysis cannot prove runtime reachability.'],
}

