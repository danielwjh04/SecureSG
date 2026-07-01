import { render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Incidents } from './Incidents'
import type { IncidentsData } from '../../api/types'

const DATA: IncidentsData = {
  incidents: [
    {
      id: 'a',
      title: 'Agent A was turned against its owner',
      source: 'Source A',
      date: 'Jan 2025',
      url: 'https://example.test/a',
    },
    {
      id: 'b',
      title: 'Agent B leaked private data',
      source: 'Source B',
      date: 'Feb 2025',
      url: 'https://example.test/b',
    },
  ],
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('Incidents', () => {
  it('renders the real incident cards, each linking out to its source', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(DATA) }),
    )

    render(<Incidents />)

    await waitFor(() =>
      expect(screen.getByText('Agent A was turned against its owner')).toBeInTheDocument(),
    )
    expect(screen.getByText('Real agents. Real breaches.')).toBeInTheDocument()
    expect(screen.getByText('Agent B leaked private data')).toBeInTheDocument()

    // The card is an external link to the source, opened in a new tab.
    const link = screen.getByText('Agent A was turned against its owner').closest('a')
    expect(link).toHaveAttribute('href', 'https://example.test/a')
    expect(link).toHaveAttribute('target', '_blank')
    expect(link).toHaveAttribute('rel', 'noreferrer')
  })

  it('omits the section entirely when the list cannot be loaded', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')))

    const { container } = render(<Incidents />)

    // Degrades to an empty list → the whole section is omitted (no heading).
    await waitFor(() => expect(container.querySelector('section')).toBeNull())
    expect(screen.queryByText('Real agents. Real breaches.')).toBeNull()
  })
})
