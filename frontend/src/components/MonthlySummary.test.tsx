import { render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { MonthlySummary } from './MonthlySummary'

function stubFetch(data: unknown): void {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => data }),
  )
}

afterEach(() => {
  vi.unstubAllGlobals()
})

it('renders a category row from the summary', async () => {
  stubFetch({
    window_days: 30,
    generated_at: '2026-06-26T00:00:00+00:00',
    categories: [
      {
        category: 'Prompt Injection',
        allow: 0,
        human_approval_required: 0,
        block: 3,
        total: 3,
      },
    ],
  })
  render(<MonthlySummary refreshTick={0} />)
  expect(await screen.findByText('Prompt Injection')).toBeInTheDocument()
  expect(screen.getByText('3')).toBeInTheDocument()
})

it('shows an empty state when there are no categories', async () => {
  stubFetch({
    window_days: 30,
    generated_at: '2026-06-26T00:00:00+00:00',
    categories: [],
  })
  render(<MonthlySummary refreshTick={0} />)
  expect(await screen.findByText(/no verdicts/i)).toBeInTheDocument()
})
