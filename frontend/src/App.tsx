import { useState } from 'react'
import { Activity, Archive, Download, FileCode2, FolderGit2, RotateCcw, Shield, ShieldAlert, Sparkles } from 'lucide-react'
import { FileInventory } from './components/FileInventory'
import { FindingsPanel } from './components/FindingsPanel'
import { ModuleGraph } from './components/ModuleGraph'
import { SeverityOverview } from './components/SeverityOverview'
import { UploadZone } from './components/UploadZone'
import { analyzeArtifact } from './services/api'
import type { AnalysisReport, ScanKind } from './types'

type Tab = 'findings' | 'files' | 'modules'

export default function App() {
  const [report, setReport] = useState<AnalysisReport | null>(null)
  const [scanKind, setScanKind] = useState<ScanKind>('extension')
  const [analyzing, setAnalyzing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [tab, setTab] = useState<Tab>('findings')

  const runAnalysis = async (file: File) => {
    setAnalyzing(true)
    setError(null)
    try {
      setReport(await analyzeArtifact(file, scanKind))
      setTab('findings')
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Analysis failed unexpectedly.')
    } finally {
      setAnalyzing(false)
    }
  }

  const reset = () => {
    setReport(null)
    setError(null)
  }

  return (
    <div className="min-h-screen bg-ink text-slate-200">
      <header className="border-b border-line/80 bg-ink/90 backdrop-blur">
        <div className="mx-auto flex max-w-[1480px] items-center justify-between px-5 py-4 lg:px-8">
          <button type="button" onClick={reset} className="flex items-center gap-3 text-left">
            <span className="flex h-9 w-9 items-center justify-center rounded-xl border border-cyan/30 bg-cyan/10 text-cyan"><Shield size={20} /></span>
            <span><strong className="block text-sm tracking-tight text-white">Extension X-Ray</strong><span className="block font-mono text-[9px] uppercase tracking-[.2em] text-slate-600">Static security lab</span></span>
          </button>
          <div className="flex items-center gap-4">
            <span className="hidden items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/5 px-3 py-1.5 font-mono text-[10px] text-emerald-400 sm:flex"><span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />LOCAL-FIRST</span>
            <span className="hidden font-mono text-[10px] uppercase tracking-wider text-slate-600 md:inline">No artifact execution</span>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1480px] px-5 py-10 lg:px-8">
        {!report ? (
          <div className="py-4 md:py-12">
            <div className="mb-7 text-center">
              <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-violet/20 bg-violet/5 px-3 py-1 font-mono text-[10px] uppercase tracking-wider text-violet"><Sparkles size={12} /> Artifact behavior intelligence</div>
              <div className="mx-auto flex w-fit rounded-xl border border-line bg-panel p-1" aria-label="Analysis type">
                {([['extension', 'Extension VSIX'], ['repository', 'Repository ZIP']] as Array<[ScanKind, string]>).map(([kind, label]) => (
                  <button
                    key={kind}
                    type="button"
                    aria-pressed={scanKind === kind}
                    disabled={analyzing}
                    onClick={() => {
                      setScanKind(kind)
                      setError(null)
                    }}
                    className={`rounded-lg px-4 py-2 text-xs font-medium transition ${scanKind === kind ? 'bg-slate-800 text-white' : 'text-slate-500 hover:text-slate-300'}`}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>
            <UploadZone analyzing={analyzing} kind={scanKind} onAnalyze={runAnalysis} />
            {error ? <div role="alert" className="mx-auto mt-5 max-w-3xl rounded-xl border border-rose-500/30 bg-rose-500/10 px-5 py-4 text-sm text-rose-200">{error}</div> : null}
            <div className="mx-auto mt-8 grid max-w-5xl gap-4 text-sm md:grid-cols-3">
              {[['Safe ingestion', 'Traversal, links, malformed archives, and decompression abuse are blocked.'], ['Traceable signals', 'Every finding includes source evidence, impact, confidence, and guidance.'], ['Honest results', 'No generic trust score. Capabilities are context, not proof of malicious intent.']].map(([title, text], index) => <div key={title} className="rounded-xl border border-line/70 bg-panel/40 p-4"><span className="mb-3 block font-mono text-[10px] text-cyan">0{index + 1}</span><h3 className="font-medium text-slate-200">{title}</h3><p className="mt-2 text-xs leading-5 text-slate-500">{text}</p></div>)}
            </div>
          </div>
        ) : (
          <ReportDashboard report={report} tab={tab} setTab={setTab} onReset={reset} />
        )}
      </main>
      <footer className="border-t border-line px-5 py-5 text-center font-mono text-[10px] uppercase tracking-wider text-slate-700">Defensive static analysis &middot; never executes uploaded artifacts</footer>
    </div>
  )
}

function ReportDashboard({ report, tab, setTab, onReset }: { report: AnalysisReport; tab: Tab; setTab: (tab: Tab) => void; onReset: () => void }) {
  const findingTotal = Object.values(report.severity_counts).reduce((sum, count) => sum + count, 0)
  const isRepository = report.analysis_kind === 'repository'
  const title = isRepository ? report.repository.name : report.extension.display_name ?? report.extension.name
  const version = isRepository ? report.repository.version : report.extension.version
  const subtitle = isRepository ? `Repository · ${report.source_filename}` : `${report.extension.publisher} · ${report.source_filename}`
  const description = isRepository ? report.repository.description : report.extension.description
  const contextTags = isRepository
    ? [...report.repository.ecosystems, ...(report.repository.package_manager ? [report.repository.package_manager] : []), ...Object.keys(report.repository.scripts).map((script) => `script:${script}`)]
    : report.extension.activation_events
  const download = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    const identity = isRepository ? report.repository.name : `${report.extension.publisher}.${report.extension.name}`
    anchor.download = `${identity.replace(/[^a-z0-9._-]+/gi, '-')}-${version ?? 'unversioned'}-xray.json`
    anchor.click()
    URL.revokeObjectURL(url)
  }
  return (
    <div>
      <section className="mb-6 flex flex-col justify-between gap-5 rounded-2xl border border-line bg-panel p-6 lg:flex-row lg:items-center">
        <div className="flex min-w-0 items-start gap-4">
          <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border border-violet/30 bg-violet/10 text-violet">{isRepository ? <FolderGit2 size={23} /> : <FileCode2 size={23} />}</span>
          <div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><h1 className="truncate text-2xl font-semibold text-white">{title}</h1>{version ? <span className="rounded-md bg-slate-800 px-2 py-1 font-mono text-[10px] text-slate-400">v{version}</span> : null}</div><p className="mt-1 text-sm text-slate-500">{subtitle}</p><p className="mt-2 truncate font-mono text-[10px] text-slate-700" title={report.sha256}>SHA-256 {report.sha256}</p></div>
        </div>
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={onReset} className="inline-flex items-center gap-2 rounded-lg border border-line px-4 py-2.5 text-xs text-slate-300 hover:border-slate-500"><RotateCcw size={15} /> New scan</button>
          <button type="button" onClick={download} className="inline-flex items-center gap-2 rounded-lg bg-cyan px-4 py-2.5 text-xs font-semibold text-ink hover:bg-emerald-200"><Download size={15} /> Download JSON</button>
        </div>
      </section>

      <div className="mb-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Metric icon={<ShieldAlert />} label="Security signals" value={String(findingTotal)} detail={findingTotal ? `${report.severity_counts.critical + report.severity_counts.high} elevated` : 'No rule matches'} />
        <Metric icon={<Archive />} label="Files inspected" value={String(report.archive.file_count)} detail={`${(report.archive.uncompressed_bytes / 1024).toFixed(1)} KiB expanded`} />
        {isRepository
          ? <Metric icon={<Activity />} label="Declared dependencies" value={String(report.repository.dependency_count)} detail={`${report.repository.workflow_count} CI workflows`} />
          : <Metric icon={<Activity />} label="Module relations" value={String(report.modules.edges.length)} detail={`${report.modules.nodes.length} graph nodes`} />}
        <Metric icon={<Sparkles />} label="REA enrichment" value={report.rea.used ? 'Active' : 'Fallback'} detail={report.rea.used ? `${report.rea.analyzed_files} sources` : report.rea.status} />
      </div>

      <div className="mb-6 grid gap-4 xl:grid-cols-[1fr_1.5fr]">
        <SeverityOverview counts={report.severity_counts} />
        <div className="rounded-2xl border border-line bg-panel p-5"><p className="font-mono text-[10px] uppercase tracking-[.2em] text-slate-500">Analysis context</p><p className="mt-3 text-sm leading-6 text-slate-300">{description ?? (isRepository ? 'No repository description was declared.' : 'No extension description was declared.')}</p><div className="mt-4 flex flex-wrap gap-2">{contextTags.slice(0, 20).map((tag) => <span key={tag} className="rounded-md border border-line bg-ink px-2 py-1 font-mono text-[10px] text-slate-400">{tag}</span>)}</div>{isRepository ? <p className="mt-4 text-xs leading-5 text-slate-500">{report.repository.manifests.length} manifests · {report.repository.security_config_files.length} automation and workspace configuration files</p> : null}<p className="mt-4 border-t border-line pt-4 text-xs leading-5 text-slate-500">{report.rea.message}</p></div>
      </div>

      <nav className="mb-4 flex gap-1 overflow-auto rounded-xl border border-line bg-panel p-1" aria-label="Report sections">
        {([['findings', `Findings (${findingTotal})`], ['files', `Files (${report.files.length})`], ['modules', `Dependencies (${report.modules.nodes.length})`]] as Array<[Tab, string]>).map(([value, label]) => <button key={value} type="button" onClick={() => setTab(value)} className={`whitespace-nowrap rounded-lg px-4 py-2.5 text-xs font-medium transition ${tab === value ? 'bg-slate-800 text-white' : 'text-slate-500 hover:text-slate-300'}`}>{label}</button>)}
      </nav>
      {tab === 'findings' ? <FindingsPanel findings={report.findings} /> : null}
      {tab === 'files' ? <FileInventory files={report.files} /> : null}
      {tab === 'modules' ? <ModuleGraph graph={report.modules} /> : null}

      <details className="mt-5 rounded-xl border border-line bg-panel px-5 py-4 text-xs text-slate-500"><summary className="cursor-pointer font-medium text-slate-300">Analysis limitations ({report.limitations.length})</summary><ul className="mt-3 list-disc space-y-2 pl-5 leading-5">{report.limitations.map((item) => <li key={item}>{item}</li>)}</ul></details>
    </div>
  )
}

function Metric({ icon, label, value, detail }: { icon: React.ReactNode; label: string; value: string; detail: string }) {
  return <div className="rounded-2xl border border-line bg-panel p-5"><div className="mb-4 flex items-center justify-between text-slate-600"><span className="[&>svg]:h-4 [&>svg]:w-4">{icon}</span><span className="font-mono text-[9px] uppercase tracking-wider">{label}</span></div><div className="text-2xl font-semibold text-white">{value}</div><p className="mt-1 text-xs text-slate-500">{detail}</p></div>
}
