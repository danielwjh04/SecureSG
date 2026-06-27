import type { ReactNode } from 'react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { Proof, ProofStep } from '../../shared/contract'
import { verifyChain } from '../../shared/proof'
import { canonicalJson } from '../../shared/canonical'
import { ProofStepRow } from './ProofStepRow'
import type { ProofStepStatus } from './ProofStepRow'
import { PROOF_REHASH_DEBOUNCE_MS } from '../config'

interface ProofViewerProps {
  proof: Proof
}

/** The client-side re-verification outcome, mirroring {@link VerifyResult}. */
interface LiveVerification {
  ok: boolean
  firstBrokenIndex: number | null
}

/**
 * Deep-clone a proof so the editable working copy never aliases the pristine
 * prop. Steps and their payloads are copied by value (payloads hold only JSON
 * primitives), so a tamper to one field can never mutate the original.
 *
 * Time complexity: O(n·k) over steps n and payload keys k.
 * Space complexity: O(n·k).
 */
function cloneProof(proof: Proof): Proof {
  return {
    genesisHash: proof.genesisHash,
    headHash: proof.headHash,
    steps: proof.steps.map((step) => ({
      index: step.index,
      kind: step.kind,
      prevHash: step.prevHash,
      currHash: step.currHash,
      payload: { ...step.payload },
    })),
  }
}

/**
 * Seed each step's editable textarea with the *canonical* JSON of its payload —
 * the exact serialization the proof hashes (`canonicalJson`, keys sorted,
 * compact separators) — so what the user sees and edits is byte-for-byte the
 * hashed form, not a re-formatted view that would drift from the chain. Indexed
 * by step index so a row's draft survives unrelated edits.
 *
 * Time complexity: O(n·k log k). Space complexity: O(n·k).
 */
function seedDrafts(proof: Proof): Record<number, string> {
  const drafts: Record<number, string> = {}
  for (const step of proof.steps) {
    drafts[step.index] = canonicalJson(step.payload)
  }
  return drafts
}

/**
 * Resolve one row's live integrity status from the latest verification.
 *
 * Until the first re-hash completes (`verification` null) every row reads as
 * `ok` — the pristine proof verifies by construction. Once a break is found,
 * the breaking row and everything after it read as `broken` (a tampered link
 * invalidates every downstream hash); earlier rows stay `ok`.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function statusFor(
  index: number,
  verification: LiveVerification | null,
): ProofStepStatus {
  if (verification === null || verification.firstBrokenIndex === null) {
    return 'ok'
  }
  return index >= verification.firstBrokenIndex ? 'broken' : 'ok'
}

/**
 * Interactive proof inspector that proves tamper-evidence *in the user's own
 * browser*: it holds a deep-cloned, editable copy of the proof, lets the user
 * mutate any step's payload, then re-runs `verifyChain` client-side (Web Crypto,
 * no network round-trip) and re-marks every row `● INTACT` / `● BROKEN`.
 *
 * On any edit the touched row's payload JSON is re-parsed into the working
 * proof and the whole chain is re-verified after a short debounce, so the chain
 * is not re-hashed on every keystroke. A malformed-JSON edit leaves the prior
 * payload in place (the chain still re-hashes, surfacing the break the edit
 * already implies) rather than throwing. "Reset proof" restores the pristine
 * proof passed in via props.
 *
 * Time complexity per re-verification: O(n) digests (one forward pass).
 * Space complexity: O(n·k) for the working copy and drafts.
 */
export function ProofViewer({ proof }: ProofViewerProps): ReactNode {
  const [working, setWorking] = useState<Proof>(() => cloneProof(proof))
  const [drafts, setDrafts] = useState<Record<number, string>>(() =>
    seedDrafts(proof),
  )
  const [verification, setVerification] = useState<LiveVerification | null>(null)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const verifyTokenRef = useRef(0)

  // Re-seed when a different proof arrives (e.g. a fresh scan or gallery pick).
  useEffect(() => {
    setWorking(cloneProof(proof))
    setDrafts(seedDrafts(proof))
    setVerification(null)
  }, [proof])

  // Debounced client-side re-verification. The token guards against a stale
  // async result overwriting a newer one (last edit wins). Runs entirely in the
  // browser via Web Crypto — there is no fetch here by design.
  useEffect(() => {
    if (debounceRef.current !== null) {
      clearTimeout(debounceRef.current)
    }
    debounceRef.current = setTimeout(() => {
      const token = ++verifyTokenRef.current
      void verifyChain(working).then((result) => {
        if (token !== verifyTokenRef.current) {
          return
        }
        setVerification(result)
      })
    }, PROOF_REHASH_DEBOUNCE_MS)
    return () => {
      if (debounceRef.current !== null) {
        clearTimeout(debounceRef.current)
      }
    }
  }, [working])

  const applyEdit = useCallback((index: number, raw: string): void => {
    setDrafts((prev) => ({ ...prev, [index]: raw }))
    setWorking((prev) => {
      let parsed: ProofStep['payload'] | null = null
      try {
        const candidate: unknown = JSON.parse(raw)
        if (
          candidate !== null &&
          typeof candidate === 'object' &&
          !Array.isArray(candidate)
        ) {
          parsed = candidate as ProofStep['payload']
        }
      } catch {
        // Malformed JSON: keep the prior payload. The re-hash still runs, so the
        // tamper the user is mid-typing is reflected once the JSON parses.
        parsed = null
      }
      if (parsed === null) {
        return prev
      }
      return {
        ...prev,
        steps: prev.steps.map((step) =>
          step.index === index ? { ...step, payload: parsed } : step,
        ),
      }
    })
  }, [])

  const reset = useCallback((): void => {
    verifyTokenRef.current += 1
    setWorking(cloneProof(proof))
    setDrafts(seedDrafts(proof))
    setVerification(null)
  }, [proof])

  const tampered = verification !== null && verification.firstBrokenIndex !== null
  const headline = useMemo(
    () =>
      tampered
        ? 'Tamper detected. The chain re-verified as BROKEN.'
        : 'Re-hashed in your browser, no server round-trip.',
    [tampered],
  )

  return (
    <div className="proof">
      <div className="proof__intro">
        <span
          className={`chain ${tampered ? 'chain--broken' : 'chain--ok'}`}
          aria-live="polite"
        >
          {tampered ? '● BROKEN' : '● CHAIN INTACT'}
        </span>
        <p className="proof__note">{headline}</p>
        <button type="button" className="btn btn--ghost" onClick={reset}>
          Reset proof
        </button>
      </div>
      <div className="proof__steps" role="list" aria-label="Proof chain steps">
        {working.steps.map((step) => (
          <ProofStepRow
            key={step.index}
            step={step}
            status={statusFor(step.index, verification)}
            editedText={drafts[step.index] ?? ''}
            onEdit={(raw) => applyEdit(step.index, raw)}
          />
        ))}
      </div>
    </div>
  )
}
