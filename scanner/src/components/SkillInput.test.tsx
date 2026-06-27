import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { SkillInput } from './SkillInput'

/**
 * Exercise the three input paths the scan box exposes: pasted content, a source
 * URL, and an uploaded `.md` file (which loads into the same content path). The
 * `onScan` callback is the contract, so each test asserts exactly what request
 * it emits.
 */
describe('SkillInput', () => {
  it('scans pasted content as `content`', () => {
    const onScan = vi.fn()
    render(<SkillInput onScan={onScan} busy={false} />)

    fireEvent.change(screen.getByLabelText('SKILL.md content'), {
      target: { value: '# Skill\nhttps://example.com' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Scan skill' }))

    expect(onScan).toHaveBeenCalledWith({ content: '# Skill\nhttps://example.com' })
  })

  it('scans a source URL as `sourceUrl` when no content is present', () => {
    const onScan = vi.fn()
    render(<SkillInput onScan={onScan} busy={false} />)

    fireEvent.change(screen.getByLabelText('Source URL'), {
      target: { value: 'https://github.com/owner/repo' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Scan skill' }))

    expect(onScan).toHaveBeenCalledWith({ sourceUrl: 'https://github.com/owner/repo' })
  })

  it('loads an uploaded .md file into the content box, then scans it', async () => {
    const onScan = vi.fn()
    render(<SkillInput onScan={onScan} busy={false} />)

    const file = new File(['# Uploaded\nhttps://example.com'], 'SKILL.md', {
      type: 'text/markdown',
    })
    fireEvent.change(screen.getByLabelText('Upload SKILL.md file'), {
      target: { files: [file] },
    })

    const area = screen.getByLabelText('SKILL.md content') as HTMLTextAreaElement
    await waitFor(() => expect(area.value).toContain('# Uploaded'))
    expect(screen.getByText(/Loaded SKILL\.md/)).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: 'Scan skill' }))
    expect(onScan).toHaveBeenCalledWith({
      content: '# Uploaded\nhttps://example.com',
    })
  })

  it('disables every control while busy', () => {
    render(<SkillInput onScan={vi.fn()} busy={true} />)

    expect(screen.getByLabelText('SKILL.md content')).toBeDisabled()
    expect(screen.getByLabelText('Source URL')).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Upload .md' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Scanning…' })).toBeDisabled()
  })
})
