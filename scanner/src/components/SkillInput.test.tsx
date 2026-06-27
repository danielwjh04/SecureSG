import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { SkillInput } from './SkillInput'

/**
 * Exercise the three input modes the segmented scan control exposes: pasted
 * content (the default mode), a source URL, and an uploaded `.md` file (which
 * loads into the content path). The `onScan` callback is the contract, so each
 * test asserts exactly what request it emits.
 */
describe('SkillInput', () => {
  it('scans pasted content as `content` in the default mode', () => {
    const onScan = vi.fn()
    render(<SkillInput onScan={onScan} busy={false} />)

    fireEvent.change(screen.getByLabelText('SKILL.md content'), {
      target: { value: '# Skill\nhttps://example.com' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Scan skill/ }))

    expect(onScan).toHaveBeenCalledWith({ content: '# Skill\nhttps://example.com' })
  })

  it('scans a source URL after switching to the URL mode', async () => {
    const onScan = vi.fn()
    render(<SkillInput onScan={onScan} busy={false} />)

    fireEvent.click(screen.getByRole('button', { name: 'URL' }))
    const urlInput = await screen.findByLabelText('Source URL')
    fireEvent.change(urlInput, {
      target: { value: 'https://github.com/owner/repo' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Scan skill/ }))

    expect(onScan).toHaveBeenCalledWith({ sourceUrl: 'https://github.com/owner/repo' })
  })

  it('loads an uploaded .md file in the upload mode, then scans it as content', async () => {
    const onScan = vi.fn()
    render(<SkillInput onScan={onScan} busy={false} />)

    fireEvent.click(screen.getByRole('button', { name: /Upload \.md/ }))
    const file = new File(['# Uploaded\nhttps://example.com'], 'SKILL.md', {
      type: 'text/markdown',
    })
    fireEvent.change(screen.getByLabelText('Upload SKILL.md file'), {
      target: { files: [file] },
    })

    await waitFor(() => expect(screen.getByText(/Loaded SKILL\.md/)).toBeTruthy())
    fireEvent.click(screen.getByRole('button', { name: /Scan skill/ }))

    expect(onScan).toHaveBeenCalledWith({
      content: '# Uploaded\nhttps://example.com',
    })
  })

  it('disables the scan action while busy', () => {
    render(<SkillInput onScan={vi.fn()} busy={true} />)
    expect(screen.getByRole('button', { name: /Scanning/ })).toBeDisabled()
  })
})
