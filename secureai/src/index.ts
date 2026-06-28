/**
 * Worker entry point. Routes `/api/*` to handlers; everything else 404s for now
 * (the SPA mounts via the ASSETS binding when the frontend lands).
 *
 * Config is loaded once per API request and fail-closed: any {@link ConfigError}
 * returns 500 before a handler runs, never entering the request path.
 */

import type { Env } from './config/env'
import { loadConfig } from './config/env'
import { handleGuard } from './routes/guard'
import { handleScan } from './routes/scan'
import { handleSignup } from './routes/signup'
import { handleVerify } from './routes/verify'
import { ParseError, ScannerError } from './errors'

const ROUTE_SCAN = '/api/scan'
const ROUTE_VERIFY = '/api/verify'
const ROUTE_GUARD = '/api/guard'
const ROUTE_SIGNUP = '/api/signup'

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)

    if (!url.pathname.startsWith('/api/')) {
      return new Response('Not found', { status: 404 })
    }

    let config
    try {
      config = loadConfig(env)
    } catch (error) {
      console.error(`config load failed: ${errorName(error)}`)
      return jsonError('configuration error', 500)
    }

    if (url.pathname === ROUTE_SCAN) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      // handleScan owns its own error→status mapping and never throws.
      return await handleScan(request, env, config)
    }

    if (url.pathname === ROUTE_GUARD) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      // handleGuard owns its own error→status mapping and never throws.
      return await handleGuard(request, env, config)
    }

    if (url.pathname === ROUTE_SIGNUP) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      // handleSignup owns its own error→status mapping and never throws.
      return await handleSignup(request, env)
    }

    if (url.pathname === ROUTE_VERIFY) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      try {
        return await handleVerify(request, config)
      } catch (error) {
        return errorResponse(error)
      }
    }

    return jsonError('not found', 404)
  },
} satisfies ExportedHandler<Env>

/** Map a thrown error to an HTTP response, logging its exact class. */
function errorResponse(error: unknown): Response {
  if (error instanceof ParseError) {
    return jsonError(error.message, 422)
  }
  if (error instanceof ScannerError) {
    console.error(`handler fault: ${error.name}: ${error.message}`)
    return jsonError(error.message, 400)
  }
  console.error(`unexpected fault: ${errorName(error)}`)
  return jsonError('internal error', 500)
}

function jsonError(message: string, status: number): Response {
  return Response.json({ error: message }, { status })
}

function errorName(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error)
}
