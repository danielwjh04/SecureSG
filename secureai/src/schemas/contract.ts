/**
 * Cross-boundary types live in one place: `@secureai/contract` (resolved via the
 * tsconfig path alias). This module re-exports them so every existing
 * `../schemas/contract` import keeps working while there is a single definition
 * site, no drift between the Worker, the SPA, and the SDK.
 */
export type * from '@secureai/contract'
