import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ContactModal } from './ContactModal'
import { ApiError } from '../api/client'
import * as client from '../api/client'

afterEach(() => {
  vi.restoreAllMocks()
})

/** Fill the three fields with the given values via their accessible labels. */
function fillForm(values: { name: string; email: string; message: string }): void {
  fireEvent.change(screen.getByLabelText('Name'), {
    target: { value: values.name },
  })
  fireEvent.change(screen.getByLabelText('Email'), {
    target: { value: values.email },
  })
  fireEvent.change(screen.getByLabelText('Message'), {
    target: { value: values.message },
  })
}

describe('ContactModal', () => {
  it('opens with the contact form fields and a submit button', () => {
    render(<ContactModal onClose={vi.fn()} />)

    expect(screen.getByRole('dialog', { name: 'Contact sales' })).toBeInTheDocument()
    expect(screen.getByLabelText('Name')).toBeInTheDocument()
    expect(screen.getByLabelText('Email')).toBeInTheDocument()
    expect(screen.getByLabelText('Message')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Submit' })).toBeInTheDocument()
  })

  it('rejects an invalid email client-side without POSTing', () => {
    const submit = vi.spyOn(client, 'submitContact')
    render(<ContactModal onClose={vi.fn()} />)

    fillForm({ name: 'Ada', email: 'not-an-email', message: 'Hello' })
    fireEvent.click(screen.getByRole('button', { name: 'Submit' }))

    expect(submit).not.toHaveBeenCalled()
    expect(screen.getByRole('alert')).toHaveTextContent('Check your details.')
  })

  it('blocks a submit when a required field is empty', () => {
    const submit = vi.spyOn(client, 'submitContact')
    render(<ContactModal onClose={vi.fn()} />)

    fillForm({ name: 'Ada', email: 'ada@co.com', message: '   ' })
    fireEvent.click(screen.getByRole('button', { name: 'Submit' }))

    expect(submit).not.toHaveBeenCalled()
    expect(screen.getByRole('alert')).toHaveTextContent('Check your details.')
  })

  it('POSTs trimmed fields and shows the success state on success', async () => {
    const submit = vi
      .spyOn(client, 'submitContact')
      .mockResolvedValue({ ok: true })
    render(<ContactModal onClose={vi.fn()} />)

    fillForm({ name: '  Ada  ', email: ' ada@co.com ', message: ' Hello ' })
    fireEvent.click(screen.getByRole('button', { name: 'Submit' }))

    await waitFor(() =>
      expect(screen.getByText("Thanks — we'll be in touch.")).toBeInTheDocument(),
    )
    expect(submit).toHaveBeenCalledWith({
      name: 'Ada',
      email: 'ada@co.com',
      message: 'Hello',
    })
    // The form is replaced by the confirmation.
    expect(screen.queryByRole('button', { name: 'Submit' })).not.toBeInTheDocument()
  })

  it('maps a 429 to the rate-limit message and keeps the form', async () => {
    vi.spyOn(client, 'submitContact').mockRejectedValue(
      new ApiError(429, 'rate limited'),
    )
    render(<ContactModal onClose={vi.fn()} />)

    fillForm({ name: 'Ada', email: 'ada@co.com', message: 'Hello' })
    fireEvent.click(screen.getByRole('button', { name: 'Submit' }))

    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent(
        'Too many requests, try again later.',
      ),
    )
    expect(screen.getByRole('button', { name: 'Submit' })).toBeInTheDocument()
  })

  it('maps a 503 to the send-unavailable message', async () => {
    vi.spyOn(client, 'submitContact').mockRejectedValue(
      new ApiError(503, 'unavailable'),
    )
    render(<ContactModal onClose={vi.fn()} />)

    fillForm({ name: 'Ada', email: 'ada@co.com', message: 'Hello' })
    fireEvent.click(screen.getByRole('button', { name: 'Submit' }))

    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent(
        "Couldn't send right now, please try again.",
      ),
    )
  })

  it('closes on the close button, the backdrop, and Escape', () => {
    const onClose = vi.fn()
    const { rerender } = render(<ContactModal onClose={onClose} />)

    fireEvent.click(screen.getByRole('button', { name: 'Close contact form' }))
    expect(onClose).toHaveBeenCalledTimes(1)

    rerender(<ContactModal onClose={onClose} />)
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(2)
  })
})
