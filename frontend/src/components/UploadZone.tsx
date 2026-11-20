import { useRef, useState } from 'react'
import { FileArchive, ScanSearch, ShieldCheck } from 'lucide-react'
import type { ScanKind } from '../types'

interface UploadZoneProps {
  analyzing: boolean
  kind: ScanKind
  onAnalyze: (file: File) => void
  onReject: (message: string) => void
}

export function UploadZone({ analyzing, kind, onAnalyze, onReject }: UploadZoneProps) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const isRepository = kind === 'repository'
  const extension = isRepository ? '.zip' : '.vsix'
  const fileLabel = isRepository ? 'repository ZIP' : 'VSIX'

  const accept = (file?: File) => {
    if (!file) return
    if (file.name.toLowerCase().endsWith(extension)) {
      onAnalyze(file)
      return
    }
    onReject(`Select a ${fileLabel} file using the ${extension} extension.`)
  }

  return (
    <section className="relative mx-auto max-w-5xl overflow-hidden rounded-3xl border border-line bg-panel/80 p-2 shadow-glow">
      <div className="scan-grid absolute inset-0 opacity-30" aria-hidden="true" />
      <div
        className={`relative flex min-h-[420px] flex-col items-center justify-center rounded-[1.25rem] border border-dashed px-6 py-14 text-center transition ${
          dragging ? 'border-cyan bg-cyan/5' : 'border-slate-700 bg-ink/55 hover:border-slate-500'
        }`}
        onDragEnter={(event) => {
          event.preventDefault()
          setDragging(true)
        }}
        onDragOver={(event) => event.preventDefault()}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault()
          setDragging(false)
          accept(event.dataTransfer.files[0])
        }}
      >
        <div className="mb-7 flex h-20 w-20 items-center justify-center rounded-2xl border border-cyan/25 bg-cyan/10 text-cyan">
          {analyzing ? <ScanSearch className="animate-pulse" size={38} /> : <FileArchive size={38} />}
        </div>
        <p className="mb-3 font-mono text-xs uppercase tracking-[0.28em] text-cyan">Local static inspection</p>
        <h2 className="max-w-2xl text-3xl font-semibold tracking-tight text-white md:text-5xl">
          {isRepository ? 'Inspect a repository ' : 'See what an extension can do '}
          <span className="text-slate-500">before you trust it.</span>
        </h2>
        <p className="mt-5 max-w-xl text-sm leading-6 text-slate-400 md:text-base">
          {isRepository
            ? 'Drop a source ZIP to inspect install hooks, CI workflows, workspace automation, wallet access, and correlated network behavior.'
            : 'Drop a VSIX to inspect capabilities, sensitive APIs, module relationships, and traceable evidence.'}
          {' '}Files stay on this machine.
        </p>
        <input
          ref={inputRef}
          className="sr-only"
          type="file"
          accept={isRepository ? '.zip,application/zip' : '.vsix,application/octet-stream'}
          aria-label={`Choose ${fileLabel} file`}
          disabled={analyzing}
          onChange={(event) => accept(event.target.files?.[0])}
        />
        <button
          type="button"
          disabled={analyzing}
          onClick={() => inputRef.current?.click()}
          className="mt-8 inline-flex items-center gap-2 rounded-xl bg-cyan px-5 py-3 text-sm font-semibold text-ink transition hover:bg-emerald-200 disabled:cursor-wait disabled:opacity-60"
        >
          <ScanSearch size={18} />
          {analyzing ? 'Analyzing safely...' : `Select a ${fileLabel}`}
        </button>
        <div className="mt-8 flex items-center gap-2 text-xs text-slate-500">
          <ShieldCheck size={15} className="text-emerald-400" />
          No execution &middot; No cloud upload &middot; 25 MiB default limit
        </div>
      </div>
    </section>
  )
}
