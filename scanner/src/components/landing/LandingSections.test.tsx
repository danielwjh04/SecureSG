import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { Problem } from './Problem'
import { Solution } from './Solution'

describe('landing sections', () => {
  it('renders the problem framing and its threat points', () => {
    render(<Problem />)
    expect(screen.getByText("Your agent trusts everything it's handed.")).toBeInTheDocument()
    expect(screen.getByText('One poisoned input is enough')).toBeInTheDocument()
    expect(screen.getByText('It happens before you can review')).toBeInTheDocument()
  })

  it('renders the solution framing with the Scanner and Guard modes', () => {
    render(<Solution />)
    expect(screen.getByText('An antivirus and a firewall for AI agents.')).toBeInTheDocument()
    expect(screen.getByText('Scanner')).toBeInTheDocument()
    expect(screen.getByText('Guard')).toBeInTheDocument()
  })
})
