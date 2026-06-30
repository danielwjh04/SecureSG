import { describe, expect, it } from 'vitest'
import type { GuardTicketContext, GuardTicketSigner, GuardTicketVerifier } from './decisionTicket'
import type { PreToolUsePayload } from '../schemas/validate'
import {
  type GuardDecisionTicket,
  guardActionHash,
  signGuardDecisionTicket,
  verifyGuardDecisionTicket,
} from './decisionTicket'

const now = new Date('2026-06-30T00:00:00.000Z')
const context = {
  signer: { alg: 'HS256', kid: 'guard-ticket-test', secret: 'test-ticket-secret' } as const,
  verifiers: [{ alg: 'HS256', kid: 'guard-ticket-test', secret: 'test-ticket-secret' } as const],
  policyVersion: 'policy-1',
  trustRevision: 'trust-1',
  ttlSeconds: 300,
  now,
}

const payload = {
  hook_event_name: 'PreToolUse',
  tool_name: 'Read',
  tool_input: { file_path: 'README.md' },
  cwd: '/workspace/project',
  device_id: 'dev_test',
  integration_version: '1.0.0',
} as PreToolUsePayload

function requireTicket(ticket: GuardDecisionTicket | null): GuardDecisionTicket {
  expect(ticket).not.toBeNull()
  return ticket as GuardDecisionTicket
}

describe('Guard decision tickets', () => {
  it('signs and verifies an exact repeated allow action', async () => {
    const ticket = requireTicket(await signGuardDecisionTicket(payload, 'allow', context))

    expect(ticket.alg).toBe('HS256')
    expect(ticket.kid).toBe('guard-ticket-test')
    expect(ticket.action_hash).toBe(await guardActionHash(payload))
    expect(ticket.policy_version).toBe('policy-1')
    expect(ticket.trust_revision).toBe('trust-1')
    expect(ticket.device_id).toBe('dev_test')

    await expect(verifyGuardDecisionTicket(payload, ticket, context)).resolves.toEqual({
      ok: true,
      reason: 'ticket valid',
    })
  })

  it('rejects a ticket when the action changes', async () => {
    const ticket = requireTicket(await signGuardDecisionTicket(payload, 'allow', context))
    const changed = { ...payload, tool_input: { file_path: '.env' } } as PreToolUsePayload

    await expect(verifyGuardDecisionTicket(changed, ticket, context)).resolves.toEqual({
      ok: false,
      reason: 'action hash mismatch',
    })
  })

  it('rejects expired and revision-mismatched tickets', async () => {
    const ticket = requireTicket(await signGuardDecisionTicket(payload, 'allow', context))

    await expect(
      verifyGuardDecisionTicket(payload, ticket, { ...context, now: new Date('2026-06-30T00:06:00.000Z') }),
    ).resolves.toEqual({ ok: false, reason: 'ticket expired' })

    await expect(
      verifyGuardDecisionTicket(payload, ticket, { ...context, policyVersion: 'policy-2' }),
    ).resolves.toEqual({ ok: false, reason: 'policy version mismatch' })
  })

  it('signGuardDecisionTicket returns null when cwd is absent', async () => {
    const noCwd = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: 'README.md' },
    } as PreToolUsePayload

    await expect(signGuardDecisionTicket(noCwd, 'allow', context)).resolves.toBeNull()
  })

  it('a ticket signed with one scope fails to verify against a different scope', async () => {
    const ticket = requireTicket(await signGuardDecisionTicket(payload, 'allow', context))
    const differentScope = { ...payload, cwd: '/workspace/other-project' } as PreToolUsePayload

    const result = await verifyGuardDecisionTicket(differentScope, ticket, context)
    expect(result.ok).toBe(false)
  })

  it('verifyGuardDecisionTicket returns missing project scope when cwd is absent', async () => {
    const ticket = requireTicket(await signGuardDecisionTicket(payload, 'allow', context))
    const noCwd = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: 'README.md' },
    } as PreToolUsePayload

    await expect(verifyGuardDecisionTicket(noCwd, ticket, context)).resolves.toEqual({
      ok: false,
      reason: 'missing project scope',
    })
  })

  it('verifies a ticket signed under the previous key id when a previous verifier is present (HS256)', async () => {
    const previousKid = 'guard-ticket-prev'
    const previousSecret = 'previous-ticket-secret'
    const currentKid = 'guard-ticket-current'
    const currentSecret = 'current-ticket-secret'

    const prevSigner: GuardTicketSigner = { alg: 'HS256', kid: previousKid, secret: previousSecret }
    const prevVerifier: GuardTicketVerifier = { alg: 'HS256', kid: previousKid, secret: previousSecret }
    const currentVerifier: GuardTicketVerifier = { alg: 'HS256', kid: currentKid, secret: currentSecret }

    // Context used to sign with the PREVIOUS key.
    const prevSignContext: GuardTicketContext = {
      signer: prevSigner,
      verifiers: [prevVerifier],
      policyVersion: 'policy-1',
      trustRevision: 'trust-1',
      ttlSeconds: 300,
      now,
    }

    // Context that knows both current and previous verifiers (rotation overlap).
    const overlapContext: GuardTicketContext = {
      signer: { alg: 'HS256', kid: currentKid, secret: currentSecret },
      verifiers: [currentVerifier, prevVerifier],
      policyVersion: 'policy-1',
      trustRevision: 'trust-1',
      ttlSeconds: 300,
      now,
    }

    const ticket = requireTicket(await signGuardDecisionTicket(payload, 'allow', prevSignContext))
    expect(ticket.kid).toBe(previousKid)

    await expect(verifyGuardDecisionTicket(payload, ticket, overlapContext)).resolves.toEqual({
      ok: true,
      reason: 'ticket valid',
    })
  })

  it('verifies a ticket signed under the previous key id when a previous verifier is present (ES256)', async () => {
    // Generate a P-256 key pair for the previous key in-test.
    const prevKeyPair = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair
    const prevPrivateJwk = (await crypto.subtle.exportKey('jwk', prevKeyPair.privateKey)) as JsonWebKey
    const prevPublicJwk = (await crypto.subtle.exportKey('jwk', prevKeyPair.publicKey)) as JsonWebKey

    // Generate a P-256 key pair for the current key in-test.
    const currKeyPair = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair
    const currPrivateJwk = (await crypto.subtle.exportKey('jwk', currKeyPair.privateKey)) as JsonWebKey
    const currPublicJwk = (await crypto.subtle.exportKey('jwk', currKeyPair.publicKey)) as JsonWebKey

    const previousKid = 'guard-ticket-es256-prev'
    const currentKid = 'guard-ticket-es256-current'

    const prevSigner: GuardTicketSigner = { alg: 'ES256', kid: previousKid, privateJwk: prevPrivateJwk }
    const prevVerifier: GuardTicketVerifier = { alg: 'ES256', kid: previousKid, publicJwk: prevPublicJwk }
    const currentVerifier: GuardTicketVerifier = { alg: 'ES256', kid: currentKid, publicJwk: currPublicJwk }

    // Context that signs with the PREVIOUS key.
    const prevSignContext: GuardTicketContext = {
      signer: prevSigner,
      verifiers: [prevVerifier],
      policyVersion: 'policy-1',
      trustRevision: 'trust-1',
      ttlSeconds: 300,
      now,
    }

    // Context with both verifiers (rotation overlap, current signer).
    const overlapContext: GuardTicketContext = {
      signer: { alg: 'ES256', kid: currentKid, privateJwk: currPrivateJwk },
      verifiers: [currentVerifier, prevVerifier],
      policyVersion: 'policy-1',
      trustRevision: 'trust-1',
      ttlSeconds: 300,
      now,
    }

    const ticket = requireTicket(await signGuardDecisionTicket(payload, 'allow', prevSignContext))
    expect(ticket.kid).toBe(previousKid)

    await expect(verifyGuardDecisionTicket(payload, ticket, overlapContext)).resolves.toEqual({
      ok: true,
      reason: 'ticket valid',
    })
  })

  it('rejects a ticket whose kid matches no verifier', async () => {
    const ticket = requireTicket(await signGuardDecisionTicket(payload, 'allow', context))
    const noMatchContext: GuardTicketContext = {
      ...context,
      verifiers: [{ alg: 'HS256', kid: 'completely-different-kid', secret: 'test-ticket-secret' }],
    }

    await expect(verifyGuardDecisionTicket(payload, ticket, noMatchContext)).resolves.toEqual({
      ok: false,
      reason: 'ticket key mismatch',
    })
  })
})
