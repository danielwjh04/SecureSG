/**
 * Public types for the SecureAI SDK.
 *
 * Every cross-boundary type is re-exported from `@secureai/contract`, the single
 * source of truth shared with the Worker and the SPA, so the SDK's view of the
 * scan, verify, and guard contracts can never drift out of sync with the server
 * (that drift is exactly what produced the `GuardDecision.verdict` nullability
 * bug). The alias erases at build, so there is no runtime dependency.
 *
 * NOTE: for an eventual public npm publish, bundle these re-exported types into
 * the emitted `.d.ts` (for example with a .d.ts bundler) so consumers do not need
 * to resolve `@secureai/contract` themselves. While the package is private this
 * is a non-issue.
 */
export type * from '@secureai/contract'

/** Client construction options (SDK-specific; not a wire contract). */
export interface SecureAiClientOptions {
  apiBase?: string
  apiKey?: string
  timeoutMs?: number
  fetch?: typeof fetch
}
