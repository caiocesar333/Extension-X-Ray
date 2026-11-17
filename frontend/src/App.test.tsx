import { fireEvent, render, screen } from '@testing-library/react'
import { afterEach, vi } from 'vitest'
import App from './App'
import { reportFixture } from './test/fixtures'

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

