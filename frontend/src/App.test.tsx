import { fireEvent, render, screen } from '@testing-library/react'
import { afterEach, vi } from 'vitest'
import App from './App'
import { reportFixture, repositoryReportFixture } from './test/fixtures'

afterEach(() => vi.restoreAllMocks())

test('analyzes an uploaded VSIX and renders the report', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => reportFixture }))
  render(<App />)

  fireEvent.change(screen.getByLabelText('Choose VSIX file'), { target: { files: [new File(['x'], 'fixture.vsix')] } })

  expect(await screen.findByText('Fixture Extension')).toBeInTheDocument()
  expect(screen.getByText('Findings (1)')).toBeInTheDocument()
  expect(screen.getAllByText('Process execution API')).toHaveLength(2)
})

test('surfaces structured API failures', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 422, json: async () => ({ detail: { code: 'unsafe_path', message: 'Unsafe archive path' } }) }))
  render(<App />)

  fireEvent.change(screen.getByLabelText('Choose VSIX file'), { target: { files: [new File(['x'], 'fixture.vsix')] } })

  expect(await screen.findByRole('alert')).toHaveTextContent('Unsafe archive path')
})

test('analyzes a repository ZIP through the repository endpoint', async () => {
  const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => repositoryReportFixture })
  vi.stubGlobal('fetch', fetchMock)
  render(<App />)

  fireEvent.click(screen.getByRole('button', { name: 'Repository ZIP' }))
  fireEvent.change(screen.getByLabelText('Choose repository ZIP file'), {
    target: { files: [new File(['x'], 'repository.zip', { type: 'application/zip' })] },
  })

  expect(await screen.findByText('repository-fixture')).toBeInTheDocument()
  expect(screen.getByText('SBOM components')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Supply Chain (1)' }))
  expect(screen.getByText('Software bill of materials')).toBeInTheDocument()
  expect(screen.getByText('GHSA-r9p9-mrjm-926w')).toBeInTheDocument()
  expect(fetchMock.mock.calls[0]?.[0]).toContain('/api/v1/analyze-repository')
})

test('explains a rejected file without calling the API', async () => {
  const fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
  render(<App />)

  fireEvent.click(screen.getByRole('button', { name: 'Repository ZIP' }))
  fireEvent.change(screen.getByLabelText('Choose repository ZIP file'), {
    target: { files: [new File(['x'], 'repository.tar')] },
  })

  expect(await screen.findByRole('alert')).toHaveTextContent(
    'Select a repository ZIP file using the .zip extension.',
  )
  expect(fetchMock).not.toHaveBeenCalled()
})

