/**
 * D1 read-replication bookmark plumbing for read-your-writes.
 *
 * A D1 session bookmark is an opaque token marking a point in the write history.
 * When a client passes its latest bookmark on the next request, that request's
 * reads are guaranteed to observe at least its own prior writes (even if served by
 * a replica). We carry the bookmark to the browser SPA in an `HttpOnly` cookie
 * (`d1b`) and accept it back via that cookie or the `x-d1-bookmark` header (for
 * API/Bearer clients that prefer a header). It is NOT a credential — it leaks no
 * account data — but `HttpOnly` keeps it out of JS for tidiness.
 */

/** Header an API client may use to carry its bookmark (checked before the cookie). */
const BOOKMARK_HEADER = 'x-d1-bookmark'
/** Cookie the SPA carries its bookmark in. */
const BOOKMARK_COOKIE = 'd1b'

/**
 * Read the caller's prior D1 bookmark from the request: the `x-d1-bookmark`
 * header first (explicit API clients), else the `d1b` cookie (the browser SPA).
 * Returns `null` when neither is present.
 *
 * Time complexity: O(c) in the cookie header length. Space complexity: O(1).
 */
export function readBookmark(request: Request): string | null {
  const header = request.headers.get(BOOKMARK_HEADER)?.trim()
  if (header !== undefined && header.length > 0) {
    return header
  }
  const cookie = request.headers.get('Cookie')
  if (cookie === null) {
    return null
  }
  for (const part of cookie.split(';')) {
    const eq = part.indexOf('=')
    if (eq === -1) {
      continue
    }
    if (part.slice(0, eq).trim() === BOOKMARK_COOKIE) {
      const value = part.slice(eq + 1).trim()
      return value.length > 0 ? value : null
    }
  }
  return null
}

/**
 * Build the response headers that hand a fresh bookmark back to the client: the
 * `x-d1-bookmark` header plus an `HttpOnly; Secure; SameSite=Lax` `d1b` cookie
 * with the given TTL. Returns an empty object when `bookmark` is `null` (no
 * session ran, or anonymous) so nothing is set.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export function bookmarkResponseInit(
  bookmark: string | null,
  ttlSeconds: number,
): { headers: Record<string, string> } {
  if (bookmark === null || bookmark.length === 0) {
    return { headers: {} }
  }
  return {
    headers: {
      [BOOKMARK_HEADER]: bookmark,
      'Set-Cookie':
        `${BOOKMARK_COOKIE}=${bookmark}; Max-Age=${ttlSeconds}; Path=/; HttpOnly; Secure; SameSite=Lax`,
    },
  }
}

/**
 * Return a copy of `response` with the bookmark header + cookie merged in. Used
 * by the worker entry to stamp the post-request bookmark onto a handler's
 * response without the handler having to know about read replication. A `null`
 * bookmark returns the response unchanged.
 *
 * Time complexity: O(h) in the header count. Space complexity: O(h).
 */
export function withBookmark(response: Response, bookmark: string | null, ttlSeconds: number): Response {
  const init = bookmarkResponseInit(bookmark, ttlSeconds)
  const keys = Object.keys(init.headers)
  if (keys.length === 0) {
    return response
  }
  const merged = new Response(response.body, response)
  for (const key of keys) {
    // append() so an existing Set-Cookie (e.g. the session cookie) is preserved.
    merged.headers.append(key, init.headers[key] as string)
  }
  return merged
}
