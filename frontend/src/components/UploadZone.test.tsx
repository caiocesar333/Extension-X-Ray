import { fireEvent, render, screen } from '@testing-library/react'
import { vi } from 'vitest'
import { UploadZone } from './UploadZone'

test('accepts a VSIX file selected by the user', async () => {
  const onAnalyze = vi.fn()
  render(<UploadZone analyzing={false} kind="extension" onAnalyze={onAnalyze} />)

  const file = new File(['fixture'], 'fixture.vsix', { type: 'application/octet-stream' })
  fireEvent.change(screen.getByLabelText('Choose VSIX file'), { target: { files: [file] } })

  expect(onAnalyze).toHaveBeenCalledWith(file)
  expect(screen.getByText('No execution · No cloud upload · 25 MiB default limit')).toBeInTheDocument()
})

test('accepts a repository ZIP and rejects a VSIX in repository mode', () => {
  const onAnalyze = vi.fn()
  render(<UploadZone analyzing={false} kind="repository" onAnalyze={onAnalyze} />)

  const input = screen.getByLabelText('Choose repository ZIP file')
  const wrongFile = new File(['fixture'], 'fixture.vsix')
  const repository = new File(['fixture'], 'fixture.zip', { type: 'application/zip' })
  fireEvent.change(input, { target: { files: [wrongFile] } })
  fireEvent.change(input, { target: { files: [repository] } })

  expect(onAnalyze).toHaveBeenCalledTimes(1)
  expect(onAnalyze).toHaveBeenCalledWith(repository)
})

