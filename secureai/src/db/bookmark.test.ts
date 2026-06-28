import { describe, expect, it } from 'vitest'
import { bookmarkResponseInit, readBookmark, withBookmark } from './bookmark'

describe('readBookmark', () => {
  it('prefers the x-d1-bookmark header over the cookie', () => {
    const req = new Request('https://x.test', {
      headers: { 'x-d1-bookmark': 'bm-header', Cookie: 'd1b=bm-cookie' },
    })
    expect(readBookmark(req)).toBe('bm-header')
  })

  it('falls back to the d1b cookie when no header is present', () => {
    const req = new Request('https://x.test', { headers: { Cookie: 'other=1; d1b=bm-cookie; x=y' } })
    expect(readBookmark(req)).toBe('bm-cookie')
  })

  it('returns null when neither header nor cookie carries a bookmark', () => {
    expect(readBookmark(new Request('https://x.test'))).toBeNull()
    expect(readBookmark(new Request('https://x.test', { headers: { Cookie: 'a=b' } }))).toBeNull()
  })
})

describe('bookmarkResponseInit', () => {
  it('emits the header and an HttpOnly/Secure/SameSite cookie for a real bookmark', () => {
    const { headers } = bookmarkResponseInit('bm-1', 60)
    expect(headers['x-d1-bookmark']).toBe('bm-1')
    expect(headers['Set-Cookie']).toContain('d1b=bm-1')
    expect(headers['Set-Cookie']).toContain('HttpOnly')
    expect(headers['Set-Cookie']).toContain('Secure')
    expect(headers['Set-Cookie']).toContain('SameSite=Lax')
    expect(headers['Set-Cookie']).toContain('Max-Age=60')
  })

  it('emits nothing for a null bookmark', () => {
    expect(bookmarkResponseInit(null, 60)).toEqual({ headers: {} })
  })
})

describe('withBookmark', () => {
  it('returns the response unchanged when the bookmark is null', () => {
    const res = Response.json({ ok: true })
    expect(withBookmark(res, null, 60)).toBe(res)
  })

  it('adds the bookmark header + cookie while preserving an existing Set-Cookie', () => {
    const res = Response.json({ ok: true }, { headers: { 'Set-Cookie': 'secureai_session=abc' } })
    const merged = withBookmark(res, 'bm-2', 60)
    expect(merged.headers.get('x-d1-bookmark')).toBe('bm-2')
    // Both the session cookie and the bookmark cookie are present (append, not overwrite).
    const setCookie = merged.headers.get('Set-Cookie') ?? ''
    expect(setCookie).toContain('secureai_session=abc')
    expect(setCookie).toContain('d1b=bm-2')
  })
})
