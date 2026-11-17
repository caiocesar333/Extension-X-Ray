import { Search } from 'lucide-react'
import { useMemo, useState } from 'react'
import type { FileEntry } from '../types'

const formatBytes = (value: number) => value < 1024 ? `${value} B` : `${(value / 1024).toFixed(1)} KiB`

export function FileInventory({ files }: { files: FileEntry[] }) {
  const [query, setQuery] = useState('')
  const visible = useMemo(
    () => files.filter((file) => file.path.toLowerCase().includes(query.toLowerCase())),
    [files, query],
  )
  return (
    <section className="overflow-hidden rounded-2xl border border-line bg-panel">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-line px-5 py-4">
        <div><h3 className="text-sm font-semibold text-white">Archive inventory</h3><p className="mt-1 text-xs text-slate-500">{files.length} safely extracted files</p></div>
        <label className="flex items-center gap-2 rounded-lg border border-line bg-ink px-3 py-2 text-slate-500 focus-within:border-cyan">
          <Search size={15} />
          <input aria-label="Search files" value={query} onChange={(event) => setQuery(event.target.value)} className="w-52 bg-transparent text-xs text-slate-200 outline-none" placeholder="Filter by path…" />
        </label>
      </div>
      <div className="max-h-[620px] overflow-auto">
        <table className="w-full min-w-[720px] text-left text-xs">
          <thead className="sticky top-0 bg-panel text-[10px] uppercase tracking-wider text-slate-500"><tr><th className="px-5 py-3">Path</th><th className="px-4 py-3">Kind</th><th className="px-4 py-3">Size</th><th className="px-5 py-3">SHA-256</th></tr></thead>
          <tbody className="divide-y divide-line">
            {visible.map((file) => <tr key={file.path} className="hover:bg-white/[.02]"><td className="px-5 py-3 font-mono text-slate-300">{file.path}</td><td className="px-4 py-3 text-slate-500">{file.kind}</td><td className="px-4 py-3 font-mono text-slate-400">{formatBytes(file.size)}</td><td className="max-w-48 truncate px-5 py-3 font-mono text-slate-600" title={file.sha256}>{file.sha256}</td></tr>)}
          </tbody>
        </table>
      </div>
    </section>
  )
}

