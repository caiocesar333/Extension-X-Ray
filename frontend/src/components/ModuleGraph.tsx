import type { ModuleGraph as Graph } from '../types'

export function ModuleGraph({ graph }: { graph: Graph }) {
  const nodes = graph.nodes.slice(0, 28)
  const ids = new Set(nodes.map((node) => node.id))
  const edges = graph.edges.filter((edge) => ids.has(edge.source) && ids.has(edge.target)).slice(0, 60)
  const positions = new Map(nodes.map((node, index) => {
    const angle = (Math.PI * 2 * index) / Math.max(nodes.length, 1) - Math.PI / 2
    const radius = index === 0 ? 0 : 195 + (index % 3) * 18
    return [node.id, { x: 320 + Math.cos(angle) * radius, y: 260 + Math.sin(angle) * radius }]
  }))
  if (!nodes.length) return <div className="rounded-2xl border border-line bg-panel p-16 text-center text-sm text-slate-500">No JavaScript module relationships were recovered.</div>
  return (
    <section className="overflow-hidden rounded-2xl border border-line bg-panel">
      <div className="flex items-center justify-between border-b border-line px-5 py-4"><div><h3 className="text-sm font-semibold text-white">Module dependency map</h3><p className="mt-1 text-xs text-slate-500">{graph.nodes.length} nodes · {graph.edges.length} relationships · {graph.source}</p></div><span className="font-mono text-[10px] text-cyan">STATIC GRAPH</span></div>
      <div className="overflow-auto bg-ink/50 p-4">
        <svg role="img" aria-label="Module dependency visualization" className="mx-auto min-w-[640px]" viewBox="0 0 640 520">
          <defs><filter id="node-glow"><feGaussianBlur stdDeviation="3" result="blur" /><feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge></filter></defs>
          {edges.map((edge, index) => { const a = positions.get(edge.source); const b = positions.get(edge.target); return a && b ? <line key={`${edge.source}-${edge.target}-${index}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="#253348" strokeWidth="1" /> : null })}
          {nodes.map((node) => { const point = positions.get(node.id)!; const color = node.kind === 'external' ? '#9277ff' : node.kind === 'builtin' ? '#f59e0b' : '#42f5d7'; return <g key={node.id} transform={`translate(${point.x} ${point.y})`}><circle r="8" fill={color} fillOpacity=".2" stroke={color} filter="url(#node-glow)" /><text y="22" textAnchor="middle" fill="#94a3b8" fontSize="9" fontFamily="monospace">{node.label.slice(0, 28)}</text></g> })}
        </svg>
      </div>
      {graph.nodes.length > nodes.length ? <p className="border-t border-line px-5 py-3 text-xs text-slate-500">Visualization shows the first {nodes.length} nodes; the JSON report contains the complete bounded graph.</p> : null}
    </section>
  )
}

