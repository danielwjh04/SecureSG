/**
 * Cross-boundary types live in one place: `@secureai/contract` (resolved via the
 * tsconfig path alias). Re-exported here so the SPA and the shared proof logic
 * keep importing from `./contract` while there is a single definition site, no
 * drift between the Worker, the SPA, and the SDK.
 */
export type * from '@secureai/contract'
