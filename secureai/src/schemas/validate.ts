/**
 * Zod schemas for every inbound request body. Per CLAUDE.md §4, external input
 * is parsed here before any logic runs; a parse failure becomes a structured
 * error at the boundary, never an unhandled throw.
 */

import { z } from 'zod'
import { GUARD_DECISION_SCOPE } from '../db/guardDevices'

const proofStepKindSchema = z.enum([
  'SKILL_INPUT',
  'URL_EXTRACTED',
  'REDIRECT_HOP',
  'REPUTATION',
  'INJECTION',
  'VERDICT',
])

const proofStepSchema = z.object({
  index: z.number().int().nonnegative(),
  kind: proofStepKindSchema,
  payload: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])),
  prevHash: z.string().min(1),
  currHash: z.string().min(1),
})

const proofSchema = z.object({
  genesisHash: z.string().min(1),
  steps: z.array(proofStepSchema),
  headHash: z.string().min(1),
})

/** Body of `POST /api/verify`. */
export const verifyRequestSchema = z.object({ proof: proofSchema })

/**
 * One MCP tool exposed by a server config. Extra tool metadata is rejected at
 * the boundary so the MCP parser receives only known, bounded fields.
 */
const mcpToolSchema = z
  .object({
    name: z.string().trim().min(1).max(200),
    description: z.string().trim().max(2000).optional(),
    permissions: z.array(z.string().trim().min(1).max(200)).max(100).optional(),
    inputSchema: z.unknown().optional(),
  })
  .strict()

/**
 * Body shape for MCP scans. It accepts the observable config and setup fields
 * the scanner can judge before install, while bounding every string/list.
 */
const mcpScanSchema = z
  .object({
    name: z.string().trim().min(1).max(200).optional(),
    transport: z.string().trim().min(1).max(50).optional(),
    command: z.string().trim().min(1).max(1000).optional(),
    args: z.array(z.string().max(1000)).max(100).optional(),
    endpoint: z.string().trim().min(1).max(2048).optional(),
    endpoints: z.array(z.string().trim().min(1).max(2048)).max(50).optional(),
    permissions: z.array(z.string().trim().min(1).max(200)).max(200).optional(),
    env: z
      .union([
        z.array(z.string().trim().min(1).max(200)).max(200),
        z.record(z.string(), z.unknown()),
      ])
      .optional(),
    tools: z.array(mcpToolSchema).max(200).optional(),
    setup: z.string().max(20000).optional(),
    config: z.unknown().optional(),
  })
  .strict()
  .refine(
    (body) => Object.values(body).some((value) => value !== undefined),
    { message: 'provide at least one MCP config field' },
  )

/**
 * Body of `POST /api/scan`. Exactly one of `content` / `sourceUrl` / `mcp` must be a
 * non-empty input.
 */
export const scanRequestSchema = z
  .object({
    content: z.string().min(1).optional(),
    sourceUrl: z.string().url().optional(),
    mcp: mcpScanSchema.optional(),
  })
  .refine(
    (body) => [body.content, body.sourceUrl, body.mcp].filter((value) => value !== undefined).length === 1,
    { message: 'provide exactly one of `content`, `sourceUrl`, or `mcp`' },
  )

/**
 * Body of `POST /api/guard`: a Claude Code PreToolUse hook payload. The literal
 * event name and a non-empty tool name are always required. The payload then
 * carries EITHER the raw `tool_input` record (balanced / investigation privacy
 * modes) OR, when the adapter runs in `maximum` privacy mode and strips the raw
 * content, the `content_hash` that stands in for it; the `.refine` requires at
 * least one so a body with neither is a parse failure (fail closed at the
 * boundary) rather than a hook that silently loses its scannable payload. The
 * optional context fields Claude Code sends (`session_id`, `transcript_path`,
 * `cwd`) are accepted when present but not required, and any further fields the
 * hook protocol adds in future pass through untouched (no `.strict()`), so a
 * protocol addition never turns a real call into a parse failure.
 */
export const preToolUseSchema = z.object({
  hook_event_name: z.literal('PreToolUse'),
  tool_name: z.string().min(1),
  tool_input: z.record(z.string(), z.unknown()).optional(),
  content_hash: z.string().min(1).optional(),
  session_id: z.string().optional(),
  transcript_path: z.string().optional(),
  cwd: z.string().optional(),
}).passthrough().refine(
  (body) => body.tool_input !== undefined || body.content_hash !== undefined,
  { message: 'provide `tool_input` (balanced/investigation) or `content_hash` (maximum privacy mode)' },
)

/** The validated PreToolUse payload `POST /api/guard` operates on. */
export type PreToolUsePayload = z.infer<typeof preToolUseSchema>

/**
 * Body of `POST /api/signup`: a single account email. Trimmed, lowercased, and
 * validated as an email so the stored value is canonical and the UNIQUE
 * constraint dedupes case/whitespace variants. `.strict()` rejects unexpected
 * fields so a malformed payload fails closed at the boundary.
 */
export const signupSchema = z
  .object({
    email: z
      .string()
      .trim()
      .toLowerCase()
      .email()
      .max(254),
  })
  .strict()

/** The validated signup payload `POST /api/signup` operates on. */
export type SignupPayload = z.infer<typeof signupSchema>

/** Bounds on a contact-sales inquiry's free-text fields. */
const CONTACT_NAME_MAX = 100
const CONTACT_MESSAGE_MAX = 5000

/**
 * Body of `POST /api/contact`: a public sales inquiry. `name` and `message` are
 * trimmed and length-bounded (so neither is empty after trimming, and both are
 * capped to bound the email payload); `email` is trimmed/lowercased/validated so
 * a reply reaches a canonical address. `.strict()` rejects unexpected fields so
 * a malformed payload fails closed at the boundary (a parse failure → 422).
 */
export const contactSchema = z
  .object({
    name: z.string().trim().min(1).max(CONTACT_NAME_MAX),
    email: z.string().trim().toLowerCase().email().max(254),
    message: z.string().trim().min(1).max(CONTACT_MESSAGE_MAX),
  })
  .strict()

/** The validated payload `POST /api/contact` operates on. */
export type ContactPayload = z.infer<typeof contactSchema>

/** Minimum password length (characters). Mirrors the shared API contract. */
const MIN_PASSWORD_LENGTH = 8
/** Upper bound on password length, to bound PBKDF2 input and reject abuse. */
const MAX_PASSWORD_LENGTH = 1024
/**
 * Upper bound on a first/last name (characters), bounding the stored display
 * string. Mirrors {@link CONTACT_NAME_MAX}: a name is input shape, not a
 * behavioral tunable, so it is a validation-layer constant like the other bounds
 * here, not a runtime config var.
 */
const NAME_MAX_LENGTH = 100

/**
 * Body of `POST /api/register`: an optional name (first + last), an account
 * email, and a password. The names are trimmed and length-bounded so the app can
 * greet the person; they are OPTIONAL at this boundary to mirror the nullable
 * `users.first_name`/`last_name` columns (an API-key / programmatic caller has no
 * name step), while the sign-up FORM requires them so every human account has a
 * name. The email is trimmed/lowercased/validated so the stored value is
 * canonical (matching {@link signupSchema}); the password is length-bounded but
 * never transformed, it is hashed verbatim. `.strict()` rejects unexpected
 * fields so a malformed payload fails closed at the boundary.
 */
export const registerSchema = z
  .object({
    firstName: z.string().trim().min(1).max(NAME_MAX_LENGTH).optional(),
    lastName: z.string().trim().min(1).max(NAME_MAX_LENGTH).optional(),
    email: z.string().trim().toLowerCase().email().max(254),
    password: z.string().min(MIN_PASSWORD_LENGTH).max(MAX_PASSWORD_LENGTH),
  })
  .strict()

/** The validated register payload `POST /api/register` operates on. */
export type RegisterPayload = z.infer<typeof registerSchema>

/**
 * Body of `POST /api/login`: an account email plus a password. The email is
 * canonicalized to match how it was stored at registration; the password is only
 * length-checked (a too-short password cannot match any stored hash anyway). A
 * generic invalid-credentials response is returned by the route, never a hint
 * about which field was wrong. `.strict()` rejects unexpected fields.
 */
export const loginSchema = z
  .object({
    email: z.string().trim().toLowerCase().email().max(254),
    password: z.string().min(1).max(MAX_PASSWORD_LENGTH),
  })
  .strict()

/** The validated login payload `POST /api/login` operates on. */
export type LoginPayload = z.infer<typeof loginSchema>

/** Number of decimal digits in a one-time 2FA code. */
const OTP_CODE_DIGITS = 6
/** Exact-length 6-digit numeric code, the only accepted OTP shape. */
const otpCodeSchema = z
  .string()
  .trim()
  .regex(new RegExp(`^[0-9]{${OTP_CODE_DIGITS}}$`), 'code must be 6 digits')

/**
 * Body of `POST /api/login/verify`: the challenge id from the login response
 * plus the 6-digit code the user received by email. The code is strictly
 * shape-validated (exactly 6 digits) before any hash work; a malformed code is a
 * 422 at the boundary, not a verify attempt. `.strict()` rejects extra fields.
 */
export const loginVerifySchema = z
  .object({
    challengeId: z.string().min(1).max(100),
    code: otpCodeSchema,
  })
  .strict()

/** The validated payload `POST /api/login/verify` operates on. */
export type LoginVerifyPayload = z.infer<typeof loginVerifySchema>

/**
 * Body of `POST /api/login/resend`: the challenge id to rotate to a fresh code.
 * `.strict()` rejects extra fields so a malformed payload fails closed.
 */
export const loginResendSchema = z
  .object({
    challengeId: z.string().min(1).max(100),
  })
  .strict()

/** The validated payload `POST /api/login/resend` operates on. */
export type LoginResendPayload = z.infer<typeof loginResendSchema>

/** Body of `POST /api/guard/devices`: register one local Guard installation. */
export const guardDeviceRegisterSchema = z
  .object({
    deviceId: z.string().trim().min(1).max(128).optional(),
    name: z.string().trim().min(1).max(120).optional(),
    integration: z.string().trim().min(1).max(80),
    scopes: z.array(z.literal(GUARD_DECISION_SCOPE)).min(1).max(4).optional(),
  })
  .strict()

/** The validated payload `POST /api/guard/devices` operates on. */
export type GuardDeviceRegisterPayload = z.infer<typeof guardDeviceRegisterSchema>

/** Body of `POST /api/guard/devices/revoke`: revoke one device credential. */
export const guardDeviceRevokeSchema = z
  .object({
    id: z.string().trim().min(1).max(100),
  })
  .strict()

/** The validated payload `POST /api/guard/devices/revoke` operates on. */
export type GuardDeviceRevokePayload = z.infer<typeof guardDeviceRevokeSchema>

/**
 * Body of `POST /api/admin/members/role`: the target account id plus the role to
 * grant it. `role` is allowlisted to exactly {`member`, `admin`} at the boundary
 * `owner` (or any other value) is a 422 here, never reaching the handler, so
 * the endpoint can never be coaxed into minting an owner (owners are conferred by
 * the email allowlist alone). `.strict()` rejects unexpected fields so a
 * malformed payload fails closed.
 */
export const memberRoleSchema = z
  .object({
    userId: z.string().min(1).max(100),
    role: z.enum(['member', 'admin']),
  })
  .strict()

/** The validated payload `POST /api/admin/members/role` operates on. */
export type MemberRolePayload = z.infer<typeof memberRoleSchema>

/**
 * Body of `POST /api/admin/members/tier`: the target account id plus the tier to
 * set it to. `tier` is allowlisted to the persisted account tiers at
 * the boundary, any other value is a 422 here, never reaching the handler, so
 * the endpoint can never write an unrecognized tier (which would fail closed on
 * the next read). `.strict()` rejects unexpected fields so a malformed payload
 * fails closed.
 */
export const memberTierSchema = z
  .object({
    userId: z.string().min(1).max(100),
    tier: z.enum(['free', 'personal', 'pro', 'enterprise']),
  })
  .strict()

/** The validated payload `POST /api/admin/members/tier` operates on. */
export type MemberTierPayload = z.infer<typeof memberTierSchema>

/**
 * Body of `POST /api/billing/change`: the paid tier to switch an existing
 * subscription to, in place. Only the self-serve paid tiers are switchable
 * (`enterprise` is contact-sales; `free` is the cancel flow). `.strict()` rejects
 * unexpected fields so a malformed payload fails closed.
 */
export const billingChangeSchema = z
  .object({
    tier: z.enum(['personal', 'pro']),
  })
  .strict()

/** The validated payload `POST /api/billing/change` operates on. */
export type BillingChangePayload = z.infer<typeof billingChangeSchema>

/**
 * Body of `POST /api/admin/members/remove`: the target account id to hard-delete.
 * `.strict()` rejects unexpected fields so a malformed payload fails closed at
 * the boundary. The route enforces the owner-only gate and the
 * cannot-remove-an-owner / cannot-remove-self rules; the schema only shape-checks
 * the id.
 */
export const removeMemberSchema = z
  .object({
    userId: z.string().min(1).max(100),
  })
  .strict()

/** The validated payload `POST /api/admin/members/remove` operates on. */
export type RemoveMemberPayload = z.infer<typeof removeMemberSchema>

/** Default recent-scans page size when the `limit` query param is absent. */
const RECENT_SCANS_DEFAULT_LIMIT = 3
/** Maximum recent-scans page size; a larger `limit` is clamped to this. */
const RECENT_SCANS_MAX_LIMIT = 20

/**
 * The `limit` query param of `GET /api/scans/recent`. Absent → the default; a
 * present value must be a positive integer string and is clamped to the max, so
 * a caller can never read an unbounded page. A non-integer / non-positive value
 * is a 422 at the route boundary.
 */
export const recentScansLimitSchema = z
  .string()
  .optional()
  .transform((raw) => (raw === undefined ? String(RECENT_SCANS_DEFAULT_LIMIT) : raw))
  .pipe(z.coerce.number().int().positive())
  .transform((value) => Math.min(value, RECENT_SCANS_MAX_LIMIT))

/** Maximum length of a search/filter `q` query param, to bound the LIKE input. */
const SEARCH_QUERY_MAX_LENGTH = 200

/**
 * The optional `q` query param shared by the admin members directory and the
 * blocked-threats report: a free-text substring, bounded to
 * {@link SEARCH_QUERY_MAX_LENGTH} chars so the bound `LIKE` input can never be
 * abused. Absent → `undefined` (no filter); a present value over the bound is a
 * 422 at the route boundary. The value is bound into a parameterized `LIKE`,
 * never interpolated into SQL.
 */
export const adminSearchQuerySchema = z.string().max(SEARCH_QUERY_MAX_LENGTH).optional()

/** Default blocked-threats page size when the `limit` query param is absent. */
const THREATS_DEFAULT_LIMIT = 50
/** Maximum blocked-threats page size; a larger `limit` is clamped to this. */
const THREATS_MAX_LIMIT = 500

/**
 * The `limit` query param of `GET /api/admin/threats`. Absent → the default; a
 * present value must be a positive integer string and is clamped to the max, so
 * a caller can never read an unbounded page. A non-integer / non-positive value
 * is a 422 at the route boundary.
 */
export const threatsLimitSchema = z
  .string()
  .optional()
  .transform((raw) => (raw === undefined ? String(THREATS_DEFAULT_LIMIT) : raw))
  .pipe(z.coerce.number().int().positive())
  .transform((value) => Math.min(value, THREATS_MAX_LIMIT))

/**
 * The `offset` query param of `GET /api/admin/threats`. Absent → 0; a present
 * value must be a non-negative integer string. A non-integer / negative value is
 * a 422 at the route boundary.
 */
export const threatsOffsetSchema = z
  .string()
  .optional()
  .transform((raw) => (raw === undefined ? '0' : raw))
  .pipe(z.coerce.number().int().nonnegative())

/**
 * Structural schema for an inbound Guard decision ticket. Mirrors
 * {@link GuardDecisionTicket} (decisionTicket.ts) and preserves the exact
 * contract of the previous hand-parser: `kid` must be non-empty (the only
 * length-checked field); all other string fields accept empty strings; unknown
 * keys are stripped (Zod default, no `.strict()` or `.passthrough()`).
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export const guardDecisionTicketSchema = z.object({
  alg: z.enum(['HS256', 'ES256']),
  kid: z.string().min(1),
  action_hash: z.string(),
  scope: z.string(),
  decision: z.enum(['allow', 'ask', 'deny']),
  policy_version: z.string(),
  trust_revision: z.string(),
  expires_at: z.string(),
  signature: z.string(),
  device_id: z.string().min(1).optional(),
  integration_version: z.string().min(1).optional(),
})
