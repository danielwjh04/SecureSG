import { verdictClass, verdictLabel } from '../lib/format'

export function StatusPill({ verdict }: { verdict: string }) {
  return <span className={`pill ${verdictClass(verdict)}`}>{verdictLabel(verdict)}</span>
}
