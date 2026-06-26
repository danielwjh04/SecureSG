import { fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import type { AlertView } from '../api/types'
import { AlertFeed } from './AlertFeed'

const ALERT: AlertView = {
  id: 'a1',
  created_at: '2026-06-26T00:00:00+00:00',
  session_id: 's',
  tool_name: 'scrape_page',
  rule_id: 'injection.signature',
  category: 'Prompt Injection',
  reason: 'matched signature',
  redacted_payload: 'ignore previous instructions',
}

afterEach(() => {
  vi.unstubAllGlobals()
})

it('renders an alert and generates a CHAIN_OK report', async () => {
  const fetchMock = vi
    .fn()
    .mockResolvedValueOnce({ ok: true, status: 200, json: async () => [ALERT] })
    .mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        alert: ALERT,
        chain_status: 'CHAIN_OK',
        first_invalid_seq: null,
        generated_at: '2026-06-26T00:00:00+00:00',
      }),
    })
  vi.stubGlobal('fetch', fetchMock)

  render(<AlertFeed refreshTick={0} />)
  expect(await screen.findByText('Prompt Injection')).toBeInTheDocument()
  fireEvent.click(screen.getByText('Flag & report'))
  expect(await screen.findByText(/CHAIN INTACT/i)).toBeInTheDocument()
})
