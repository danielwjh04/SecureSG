import { render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { VerifyIt } from './VerifyIt'
import type { GalleryData } from '../api/types'

/** A minimal gallery with one benign and one BLOCK entry to derive stats from. */
const SAMPLE_GALLERY: GalleryData = {
  generatedAt: '2026-06-28T00:00:00.000Z',
  entries: [
    {
      id: 'benign-1',
      title: 'A safe skill',
      tag: 'benign',
      // @ts-expect-error, only the fields deriveStats reads are needed here.
      result: { verdict: 'ALLOW', proof: { steps: [{}, {}, {}] } },
    },
    {
      id: 'attack-1',
      title: 'A malicious skill',
      tag: 'attack',
      // @ts-expect-error, only the fields deriveStats reads are needed here.
      result: { verdict: 'BLOCK', proof: { steps: [{}, {}] } },
    },
  ],
}

function mockGallery(data: GalleryData): void {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(JSON.stringify(data), { status: 200 })),
  )
}

describe('VerifyIt', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('renders the proof-moat heading and eyebrow', () => {
    mockGallery({ generatedAt: '', entries: [] })
    render(<VerifyIt />)
    expect(screen.getByText("Don't trust us")).toBeInTheDocument()
    expect(screen.getByText('Verify it yourself.')).toBeInTheDocument()
    expect(
      screen.getByText(/SHA-256 hash chain over the evidence/i),
    ).toBeInTheDocument()
  })

  it('sits in the How it works page rhythm with an asymmetric top/bottom padding', () => {
    mockGallery({ generatedAt: '', entries: [] })
    const { container } = render(<VerifyIt />)
    const section = container.querySelector('#verify')
    expect(section).not.toBeNull()
    // VerifyIt is the last section on the How it works page (after HowItWorks and
    // EaseOfUse), not a scroll-target, so it uses the standard page rhythm
    // (pt-10 pb-20) rather than a large navbar-clearing top pad.
    expect(section?.className).toContain('pt-10')
    expect(section?.className).toContain('pb-20')
    expect(section?.className).not.toContain('py-20')
  })

  it('depicts the real scan -> verify round trip with both outcomes', () => {
    mockGallery({ generatedAt: '', entries: [] })
    render(<VerifyIt />)
    expect(screen.getByText(/\/api\/scan/)).toBeInTheDocument()
    expect(screen.getByText(/\/api\/verify/)).toBeInTheDocument()
    // CHAIN_OK / CHAIN_BROKEN appear both in the code box and as pills.
    expect(screen.getAllByText(/CHAIN_OK/).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/CHAIN_BROKEN/).length).toBeGreaterThan(0)
  })

  it('renders gallery-derived live stats (skills, threats, proof links)', async () => {
    mockGallery(SAMPLE_GALLERY)
    render(<VerifyIt />)
    // 2 entries, 1 BLOCK, 3 + 2 = 5 proof steps.
    await waitFor(() => {
      expect(screen.getByText('Skills scanned')).toBeInTheDocument()
      expect(screen.getByText('2')).toBeInTheDocument() // skills
      expect(screen.getByText('1')).toBeInTheDocument() // threats (BLOCK)
      expect(screen.getByText('5')).toBeInTheDocument() // proof links
    })
  })

  it('degrades gracefully when the gallery is empty (stats read zero)', async () => {
    mockGallery({ generatedAt: '', entries: [] })
    render(<VerifyIt />)
    await waitFor(() => {
      // All three stats collapse to 0; the section still renders.
      expect(screen.getAllByText('0').length).toBeGreaterThanOrEqual(3)
    })
    expect(screen.getByText('Threats caught')).toBeInTheDocument()
  })

  it('degrades gracefully when the gallery fetch fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('network down')
      }),
    )
    render(<VerifyIt />)
    // The section heading still renders even though the fetch rejected.
    expect(screen.getByText('Verify it yourself.')).toBeInTheDocument()
    await waitFor(() => {
      expect(screen.getAllByText('0').length).toBeGreaterThanOrEqual(3)
    })
  })
})
