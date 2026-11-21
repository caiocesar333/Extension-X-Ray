import { Download, PackageCheck, ShieldAlert } from 'lucide-react'
import type { CycloneDxBom, SupplyChainSummary } from '../types'

interface SupplyChainPanelProps {
  repositoryName: string
  sbom: CycloneDxBom
  summary: SupplyChainSummary
}

const severityClass = {
  critical: 'border-rose-500/30 bg-rose-500/10 text-rose-300',
  high: 'border-orange-500/30 bg-orange-500/10 text-orange-300',
  medium: 'border-amber-500/30 bg-amber-500/10 text-amber-200',
  low: 'border-sky-500/30 bg-sky-500/10 text-sky-300',
  info: 'border-slate-600 bg-slate-800 text-slate-300',
}

export function SupplyChainPanel({ repositoryName, sbom, summary }: SupplyChainPanelProps) {
  const download = () => {
    const blob = new Blob([JSON.stringify(sbom, null, 2)], { type: 'application/vnd.cyclonedx+json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `${repositoryName.replace(/[^a-z0-9._-]+/gi, '-')}-bom.cdx.json`
    anchor.click()
    URL.revokeObjectURL(url)
  }

  return (
    <section className="space-y-4">
      <div className="rounded-2xl border border-line bg-panel p-5">
        <div className="flex flex-col justify-between gap-4 md:flex-row md:items-start">
          <div>
            <p className="font-mono text-[10px] uppercase tracking-[.2em] text-cyan">CycloneDX 1.6</p>
            <h2 className="mt-2 text-lg font-semibold text-white">Software bill of materials</h2>
            <p className="mt-2 max-w-3xl text-xs leading-5 text-slate-500">
              {summary.advisory_database.message} Snapshot: {summary.advisory_database.snapshot_date ?? 'unavailable'}.
            </p>
          </div>
          <button type="button" onClick={download} className="inline-flex items-center justify-center gap-2 rounded-lg border border-cyan/30 px-4 py-2.5 text-xs text-cyan hover:bg-cyan/5">
            <Download size={15} /> Download CycloneDX
          </button>
        </div>
        <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <SupplyMetric label="Components" value={summary.component_count} />
          <SupplyMetric label="Strong integrity" value={summary.lockfile.integrity_count} />
          <SupplyMetric label="Missing integrity" value={summary.lockfile.missing_integrity_count} />
          <SupplyMetric label="Advisory matches" value={summary.advisory_matches.length} />
        </div>
        {summary.advisory_database.coverage ? <p className="mt-4 rounded-lg border border-amber-500/20 bg-amber-500/5 px-3 py-2 text-xs leading-5 text-amber-200/80">{summary.advisory_database.coverage}</p> : null}
      </div>

      {summary.advisory_matches.length ? (
        <div className="rounded-2xl border border-line bg-panel p-5">
          <div className="mb-4 flex items-center gap-2"><ShieldAlert size={17} className="text-amber-300" /><h2 className="font-semibold text-white">Offline advisory matches</h2></div>
          <div className="space-y-3">
            {summary.advisory_matches.map((advisory) => (
              <article key={`${advisory.advisory_id}-${advisory.package}-${advisory.version}`} className="rounded-xl border border-line bg-ink/60 p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`rounded-md border px-2 py-1 font-mono text-[10px] uppercase ${severityClass[advisory.severity]}`}>{advisory.severity}</span>
                  <strong className="text-sm text-white">{advisory.advisory_id}</strong>
                  <span className="font-mono text-xs text-slate-500">{advisory.package}@{advisory.version}</span>
                </div>
                <p className="mt-3 text-sm text-slate-300">{advisory.summary}</p>
                <p className="mt-2 text-xs text-slate-500">Fixed version: {advisory.fixed_version ?? 'not declared in snapshot'}</p>
                {advisory.reference ? <a href={advisory.reference} target="_blank" rel="noreferrer" className="mt-3 inline-block text-xs text-cyan hover:underline">Open advisory reference</a> : null}
              </article>
            ))}
          </div>
        </div>
      ) : null}

      <div className="rounded-2xl border border-line bg-panel p-5">
        <div className="mb-4 flex items-center gap-2"><PackageCheck size={17} className="text-cyan" /><h2 className="font-semibold text-white">Resolved components</h2></div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[680px] text-left text-xs">
            <thead className="border-b border-line font-mono uppercase tracking-wider text-slate-600"><tr><th className="px-3 py-3">Package</th><th className="px-3 py-3">Version</th><th className="px-3 py-3">Scope</th><th className="px-3 py-3">Integrity</th></tr></thead>
            <tbody>{sbom.components.slice(0, 200).map((component) => <tr key={component['bom-ref']} className="border-b border-line/60 text-slate-400"><td className="px-3 py-3 font-mono text-slate-300">{component.group ? `@${component.group}/` : ''}{component.name}</td><td className="px-3 py-3">{component.version}</td><td className="px-3 py-3">{component.scope}</td><td className="px-3 py-3">{component.hashes[0]?.alg ?? 'missing'}</td></tr>)}</tbody>
          </table>
        </div>
        {sbom.components.length > 200 ? <p className="mt-3 text-xs text-slate-600">Showing 200 of {sbom.components.length} components. The downloaded BOM contains all admitted components.</p> : null}
      </div>
    </section>
  )
}

function SupplyMetric({ label, value }: { label: string; value: number }) {
  return <div className="rounded-xl border border-line bg-ink/50 p-3"><p className="font-mono text-[9px] uppercase tracking-wider text-slate-600">{label}</p><p className="mt-2 text-xl font-semibold text-white">{value}</p></div>
}
