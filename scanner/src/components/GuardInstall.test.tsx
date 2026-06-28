import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { GuardInstall } from './GuardInstall'
import { GUARD_DOWNLOAD_PATH, GUARD_INSTALL_COMMAND } from '../config'

afterEach(() => {
  vi.restoreAllMocks()
})

describe('GuardInstall', () => {
  it('renders the download link pointing at the guard with a download attribute', () => {
    render(<GuardInstall />)
    const download = screen.getByRole('link', { name: /Download the Guard/ })
    expect(download).toHaveAttribute('href', GUARD_DOWNLOAD_PATH)
    expect(download).toHaveAttribute('download')
  })

  it('renders the one-line installer command', () => {
    render(<GuardInstall />)
    expect(screen.getByText(GUARD_INSTALL_COMMAND)).toBeInTheDocument()
  })

  it('copies the installer command and confirms with "Copied"', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.assign(navigator, { clipboard: { writeText } })

    render(<GuardInstall />)

    const copyButton = screen.getByRole('button', { name: /Copy install command/ })
    fireEvent.click(copyButton)

    expect(writeText).toHaveBeenCalledWith(GUARD_INSTALL_COMMAND)
    await waitFor(() => expect(copyButton).toHaveTextContent('Copied'))
  })
})
