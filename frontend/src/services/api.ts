import type { AnalysisReport, ScanKind } from '../types'

const API_BASE = import.meta.env.VITE_API_URL ?? ''

export class ApiError extends Error {
  constructor(
    message: string,
    readonly code = 'request_failed',
  ) {
    super(message)
  }
}

export async function analyzeArtifact(file: File, kind: ScanKind): Promise<AnalysisReport> {
  const body = new FormData()
  body.append('file', file)
  let response: Response
  try {
    const endpoint = kind === 'repository' ? '/api/v1/analyze-repository' : '/api/v1/analyze'
    response = await fetch(`${API_BASE}${endpoint}`, { method: 'POST', body })
  } catch {
    throw new ApiError('Could not reach the local analyzer. Is the backend running?', 'network_error')
  }
  if (!response.ok) {
    const error = (await response.json().catch(() => null)) as
      | { detail?: { code?: string; message?: string } }
      | null
    throw new ApiError(
      error?.detail?.message ?? `Analysis failed with HTTP ${response.status}`,
      error?.detail?.code,
    )
  }
  return (await response.json()) as AnalysisReport
}

