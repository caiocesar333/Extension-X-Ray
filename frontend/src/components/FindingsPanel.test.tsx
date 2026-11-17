import { render, screen } from '@testing-library/react'
import { FindingsPanel } from './FindingsPanel'
import { reportFixture } from '../test/fixtures'

test('shows traceable finding evidence and guidance', () => {
  render(<FindingsPanel findings={reportFixture.findings} />)

  expect(screen.getAllByText('Process execution API').length).toBeGreaterThan(0)
  expect(screen.getByText("cp.exec('demo')")).toBeInTheDocument()
  expect(screen.getByText('Trace arguments.')).toBeInTheDocument()
  expect(screen.getByText('EXR-PROC-001')).toBeInTheDocument()
})

