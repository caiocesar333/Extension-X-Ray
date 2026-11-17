import type { Severity } from '../types'

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const COLORS: Record<Severity, string> = {
  critical: 'bg-fuchsia-500',
  high: 'bg-rose-500',
  medium: 'bg-amber-400',
  low: 'bg-sky-400',
  info: 'bg-slate-500',
}

export function SeverityOverview({ counts }: { counts: Record<Severity, number> }) {
  const findingTotal = Object.values(counts).reduce((sum, value) => sum + value, 0)
  const total = Math.max(1, findingTotal)
  return (
    <div className="rounded-2xl border border-line bg-panel p-5">
      <div className="mb-5 flex items-center justify-between">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-slate-500">Signal distribution</p>
          <h3 className="mt-1 text-lg font-semibold text-white">Finding severity</h3>
        </div>
        <span className="font-mono text-2xl text-white">{findingTotal}</span>
      </div>
      <div className="mb-5 flex h-2 overflow-hidden rounded-full bg-slate-800">
        {ORDER.map((severity) =>
          counts[severity] ? (
            <span key={severity} className={COLORS[severity]} style={{ width: `${(counts[severity] / total) * 100}%` }} />
          ) : null,
        )}
      </div>
      <div className="grid grid-cols-5 gap-2">
        {ORDER.map((severity) => (
          <div key={severity}>
            <div className="mb-1 flex items-center gap-1.5">
              <span className={`h-1.5 w-1.5 rounded-full ${COLORS[severity]}`} />
              <span className="truncate text-[10px] uppercase text-slate-500">{severity}</span>
            </div>
            <span className="font-mono text-base text-slate-200">{counts[severity]}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

