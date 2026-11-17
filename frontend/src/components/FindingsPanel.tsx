import { AlertTriangle, CheckCircle2, Code2, Crosshair } from 'lucide-react'
import { useEffect, useState } from 'react'
import type { Finding, Severity } from '../types'

const BADGE: Record<Severity, string> = {
  critical: 'border-fuchsia-500/30 bg-fuchsia-500/10 text-fuchsia-300',
  high: 'border-rose-500/30 bg-rose-500/10 text-rose-300',
  medium: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
  low: 'border-sky-500/30 bg-sky-500/10 text-sky-300',
  info: 'border-slate-500/30 bg-slate-500/10 text-slate-300',
}

export function FindingsPanel({ findings }: { findings: Finding[] }) {
  const [selectedId, setSelectedId] = useState(findings[0]?.id)
  const [filter, setFilter] = useState<Severity | 'all'>('all')
  useEffect(() => setSelectedId(findings[0]?.id), [findings])
  const visible = filter === 'all' ? findings : findings.filter((item) => item.severity === filter)
  const selected = findings.find((item) => item.id === selectedId) ?? visible[0]

  if (!findings.length) {
    return (
      <div className="flex min-h-72 flex-col items-center justify-center rounded-2xl border border-emerald-500/20 bg-emerald-500/5 text-center">
        <CheckCircle2 className="mb-4 text-emerald-400" size={36} />
        <h3 className="text-lg font-semibold text-white">No rule matches found</h3>
        <p className="mt-2 max-w-lg text-sm text-slate-400">This is not proof of safety. Review the declared capabilities and analysis limitations before making a trust decision.</p>
      </div>
    )
  }

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(360px,.85fr)]">
      <section className="overflow-hidden rounded-2xl border border-line bg-panel">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-5 py-4">
          <h3 className="text-sm font-semibold text-white">Detected signals</h3>
          <select
            aria-label="Filter severity"
            className="rounded-lg border border-line bg-ink px-3 py-1.5 text-xs text-slate-300 outline-none focus:border-cyan"
            value={filter}
            onChange={(event) => setFilter(event.target.value as Severity | 'all')}
          >
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
        <div className="max-h-[650px] divide-y divide-line overflow-auto">
          {visible.map((finding) => (
            <button
              key={finding.id}
              type="button"
              onClick={() => setSelectedId(finding.id)}
              className={`w-full px-5 py-4 text-left transition hover:bg-white/[.025] ${selected?.id === finding.id ? 'bg-cyan/[.045]' : ''}`}
            >
              <div className="mb-2 flex items-center justify-between gap-3">
                <span className={`rounded-md border px-2 py-0.5 font-mono text-[10px] uppercase ${BADGE[finding.severity]}`}>{finding.severity}</span>
                <span className="font-mono text-[10px] text-slate-600">{finding.rule_id}</span>
              </div>
              <p className="text-sm font-medium text-slate-100">{finding.title}</p>
              <p className="mt-1 truncate font-mono text-[11px] text-slate-500">
                {finding.location?.file}:{finding.location?.line ?? '?'}
              </p>
            </button>
          ))}
        </div>
      </section>
      {selected ? <EvidenceViewer finding={selected} /> : null}
    </div>
  )
}

function EvidenceViewer({ finding }: { finding: Finding }) {
  return (
    <aside className="rounded-2xl border border-line bg-panel p-5 xl:sticky xl:top-4 xl:self-start">
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-cyan">Evidence viewer</p>
          <h3 className="mt-2 text-xl font-semibold text-white">{finding.title}</h3>
        </div>
        <AlertTriangle className="shrink-0 text-amber-400" size={20} />
      </div>
      <p className="text-sm leading-6 text-slate-400">{finding.description}</p>
      <div className="my-5 rounded-xl border border-line bg-ink p-4">
        <div className="mb-3 flex items-center gap-2 font-mono text-[10px] text-slate-500">
          <Code2 size={14} /> {finding.location?.file}:{finding.location?.line ?? '?'}
        </div>
        <pre className="overflow-x-auto whitespace-pre-wrap break-words font-mono text-xs leading-5 text-cyan/90">{finding.evidence.snippet ?? finding.evidence.summary}</pre>
      </div>
      <dl className="space-y-4 text-sm">
        <div>
          <dt className="mb-1 flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-slate-500"><Crosshair size={13} /> Potential impact</dt>
          <dd className="leading-6 text-slate-300">{finding.potential_impact}</dd>
        </div>
        <div>
          <dt className="mb-1 text-xs font-medium uppercase tracking-wide text-slate-500">Investigation guidance</dt>
          <dd className="leading-6 text-slate-300">{finding.guidance}</dd>
        </div>
      </dl>
      <div className="mt-5 flex flex-wrap gap-2">
        {finding.tags.map((tag) => <span key={tag} className="rounded-md bg-slate-800 px-2 py-1 font-mono text-[10px] text-slate-400">{tag}</span>)}
      </div>
    </aside>
  )
}

