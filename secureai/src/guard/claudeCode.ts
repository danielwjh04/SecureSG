/**
 * Claude Code PreToolUse guard — the inline interceptor that routes an agent's
 * tool calls through the SecureAI scanner and turns the scanner verdict into a
 * Claude Code permission decision (allow / ask / deny), fail-closed.
 *
 * A PreToolUse hook is invoked by Claude Code *before* a tool runs. The hook is
 * handed the tool name and its inputs and may instruct the agent to proceed,
 * pause for human approval, or refuse outright. SecureAI's job here is to treat
 * the tool call as untrusted content, scan it with the same pure
 * {@link runScan} orchestrator the `/api/scan` route uses, and map its
 * {@link Verdict} onto that permission decision.
 *
 * Safety posture (CLAUDE.md §1, §6):
 *   - Fail-closed: any unexpected internal fault (scanner crash, inference
 *     transport error, malformed dependency) yields `deny`, never `allow`. The
 *     exact error class is logged via `console.error`; the agent is never let
 *     through on a fault.
 *   - "Nothing to scan" is NOT a fault: a tool call with no URLs and no
 *     download-execute pattern carries no supply-chain indicator the scanner can
 *     reason about, so it is `allow` with a `null` verdict — distinguished from a
 *     real fault by catching {@link ParseError} specifically rather than by
 *     string-matching a message.
 *   - Tighten-only: the decision is derived solely from the scanner verdict; this
 *     module never relaxes a BLOCK into an allow.
 *
 * Pure over its injected {@link ScanDeps}: no environment, clock, or network is
 * read directly here. The route layer (`routes/guard.ts`) wires the real deps.
 */

import type { ScanDeps } from '../scanner/runScan'
import type { Proof, Verdict } from '../schemas/contract'
import type { PreToolUsePayload } from '../schemas/validate'
import { ParseError } from '../errors'
import { parseSkill } from '../pipeline/parse'
import { runScan } from '../scanner/runScan'

/**
 * The Claude Code permission decision a PreToolUse hook may return.
 *   - `allow` — the tool call proceeds without prompting the user.
 *   - `ask`   — Claude Code prompts the user for approval before proceeding.
 *   - `deny`  — the tool call is blocked and the reason is fed back to the agent.
 */
export type GuardPermissionDecision = 'allow' | 'ask' | 'deny'

/**
 * The guard's decision for one tool call. `verdict` is the underlying scanner
 * verdict, or `null` when nothing scannable was present (the decision is then a
 * benign `allow`). `proof` is the tamper-evident scan proof when a scan ran, so
 * the decision can be independently re-verified (omitted when no scan ran).
 */
export interface GuardDecision {
  decision: GuardPermissionDecision
  reason: string
  verdict: Verdict | null
  proof?: Proof
}

/**
 * Map a scanner {@link Verdict} to the corresponding Claude Code permission
 * decision. The mapping is total and exhaustive (a `match` over the three-state
 * enum), so a new verdict value would be a compile error rather than a silent
 * fall-through.
 *
 *   ALLOW                    → allow
 *   HUMAN_APPROVAL_REQUIRED  → ask
 *   BLOCK                    → deny
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function verdictToDecision(verdict: Verdict): GuardPermissionDecision {
  switch (verdict) {
    case 'ALLOW':
      return 'allow'
    case 'HUMAN_APPROVAL_REQUIRED':
      return 'ask'
    case 'BLOCK':
      return 'deny'
  }
}

/**
 * The maximum number of finding details folded into a decision reason. Reasons
 * are surfaced to the agent and the user, so the most severe few findings are
 * enough; an unbounded join would bloat the hook output.
 */
const MAX_REASON_FINDINGS = 3

/**
 * Build a concise, human-readable reason from a scan result. Deterministic rule
 * findings and AI injection findings are both surfaced (rules first, since they
 * are the explainable baseline), capped at {@link MAX_REASON_FINDINGS}. When no
 * finding carries a detail, a verdict-derived fallback keeps the reason
 * non-empty.
 *
 * Time complexity: O(f) in the finding count. Space complexity: O(f).
 */
function buildReason(
  verdict: Verdict,
  findings: readonly { detail: string }[],
  injections: readonly { rationale: string; category: string }[],
): string {
  const details: string[] = []
  for (const finding of findings) {
    if (finding.detail.length > 0) {
      details.push(finding.detail)
    }
  }
  for (const injection of injections) {
    if (injection.rationale.length > 0) {
      details.push(`${injection.category}: ${injection.rationale}`)
    }
  }

  if (details.length === 0) {
    return verdict === 'ALLOW'
      ? 'no risk indicators in tool call'
      : `scanner verdict ${verdict} with no itemized findings`
  }
  return details.slice(0, MAX_REASON_FINDINGS).join('; ')
}

/**
 * Serialize a PreToolUse tool call into the scannable text the scanner consumes.
 * The tool name and its inputs are concatenated so any URL or download-execute
 * pattern embedded in either is surfaced by the deterministic parser exactly as
 * it would be in a pasted skill document.
 *
 * Time complexity: O(n) in the serialized size. Space complexity: O(n).
 */
function buildScannableContent(payload: PreToolUsePayload): string {
  return `${payload.tool_name}\n${JSON.stringify(payload.tool_input)}`
}

/**
 * True when the scannable content carries no indicator the scanner can reason
 * about (no URLs and no download-execute pattern). Detected by running the same
 * deterministic {@link parseSkill} the scanner runs and catching its
 * {@link ParseError} "nothing to scan" signal — NOT by string-matching a
 * message. Any OTHER `ParseError` (e.g. the content exceeds the configured byte
 * ceiling) is a real fault and is re-thrown so the caller fails closed.
 *
 * Doing this pre-check up front lets the guard distinguish "benign, nothing to
 * scan" (→ allow) from "the scan itself faulted" (→ deny) cleanly: if the
 * pre-check says there ARE indicators, a later `ParseError` from `runScan` is a
 * genuine fault, not an empty input.
 *
 * Time complexity: O(n) in the content length (one parser pass).
 * Space complexity: O(u + e) in the extracted URL / exec-pattern counts.
 *
 * @throws {ParseError} If `parseSkill` fails for any reason OTHER than "nothing
 *   to scan" (e.g. oversize input) — a real fault the caller fail-closes on.
 */
function hasScannableIndicators(content: string, deps: ScanDeps): boolean {
  try {
    parseSkill(content, deps.config)
    return true
  } catch (error: unknown) {
    if (error instanceof ParseError && content.length <= deps.config.skillMaxBytes) {
      // The only ParseError `parseSkill` raises on within-limit text is the
      // "no URLs and no download-execute patterns" signal: nothing to scan.
      return false
    }
    throw error
  }
}

/**
 * The fail-closed decision returned when an unexpected internal fault occurs.
 * Centralized so every fault path produces an identical, deny-by-default shape.
 */
const FAIL_CLOSED_DECISION: GuardDecision = {
  decision: 'deny',
  reason: 'SecureAI guard could not verify this tool call; blocked fail-closed',
  verdict: null,
}

/**
 * Evaluate a Claude Code PreToolUse tool call and return a permission decision.
 *
 * Pipeline:
 *   1. Serialize the tool call to scannable content (tool name + inputs).
 *   2. Pre-check for scannable indicators. None → `allow` with a `null` verdict
 *      (benign; nothing to scan). This is the clean split from a real fault.
 *   3. Run the full {@link runScan} orchestrator over the content.
 *   4. Map its {@link Verdict} to a decision and fold the findings into a reason.
 *   5. Any unexpected throw → fail-closed `deny` (logged by error class).
 *
 * Time complexity: dominated by `runScan` (O(U·H + R + F)).
 * Space complexity: O(result size).
 *
 * @param payload - The validated PreToolUse payload.
 * @param deps - Injected scanner dependencies (config, reputation, inference,
 *   fetch, scannedAt). Identical to what `/api/scan` injects.
 * @returns A {@link GuardDecision}. Never throws: every fault is mapped to a
 *   fail-closed `deny`.
 */
export async function guardDecision(
  payload: PreToolUsePayload,
  deps: ScanDeps,
): Promise<GuardDecision> {
  const content = buildScannableContent(payload)

  try {
    if (!hasScannableIndicators(content, deps)) {
      return { decision: 'allow', reason: 'no scannable indicators', verdict: null }
    }

    const { result } = await runScan({ content }, deps)
    const decision = verdictToDecision(result.verdict)
    const reason = buildReason(result.verdict, result.findings, result.injections)

    return { decision, reason, verdict: result.verdict, proof: result.proof }
  } catch (error: unknown) {
    // Fail-closed (CLAUDE.md §1, §6): an unexpected fault must never ALLOW. Log
    // the exact class so the fault is never swallowed silently.
    const className = error instanceof Error ? error.constructor.name : typeof error
    console.error(`[guardDecision] ${className}: failing closed (deny)`)
    return FAIL_CLOSED_DECISION
  }
}
