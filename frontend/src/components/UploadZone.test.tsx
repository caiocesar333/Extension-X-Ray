import { fireEvent, render, screen } from '@testing-library/react'
import { vi } from 'vitest'
import { UploadZone } from './UploadZone'

test('accepts a VSIX file selected by the user', async () => {
  const onAnalyze = vi.fn()
  render(<UploadZone analyzing={false} onAnalyze={onAnalyze} />)

  const file = new File(['fixture'], 'fixture.vsix', { type: 'application/octet-stream' })
  fireEvent.change(screen.getByLabelText('Choose VSIX file'), { target: { files: [file] } })

  expect(onAnalyze).toHaveBeenCalledWith(file)
  expect(screen.getByText('No execution · No cloud upload · 25 MiB default limit')).toBeInTheDocument()
})

