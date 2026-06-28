import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { EaseOfUse } from './EaseOfUse'

describe('EaseOfUse', () => {
  it('renders the three-step ease-of-use explainer', () => {
    render(<EaseOfUse />)
    expect(screen.getByText('Protected in one line')).toBeInTheDocument()
    expect(screen.getByText('Sign up & grab your key')).toBeInTheDocument()
    expect(screen.getByText('Drop in the Guard')).toBeInTheDocument()
    expect(screen.getByText('Risky calls get blocked')).toBeInTheDocument()
  })

  it('does not render a download button (the download lives in the dashboard)', () => {
    render(<EaseOfUse />)
    expect(screen.queryByRole('link', { name: /Download the Guard/ })).toBeNull()
    expect(screen.queryByText(/Download the Guard/)).toBeNull()
  })

  it('points users to the dashboard for the Guard and install command', () => {
    render(<EaseOfUse />)
    const dashboardLink = screen.getByRole('link', { name: 'dashboard' })
    expect(dashboardLink).toHaveAttribute('href', '#dashboard')
  })
})
