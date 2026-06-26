export function formatTimestamp(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

const VERDICT_CLASS: Record<string, string> = {
  ALLOW: 'pill--allow',
  HUMAN_APPROVAL_REQUIRED: 'pill--approval',
  BLOCK: 'pill--block',
}

export function verdictClass(verdict: string): string {
  return VERDICT_CLASS[verdict] ?? 'pill--approval'
}

export function verdictLabel(verdict: string): string {
  return verdict === 'HUMAN_APPROVAL_REQUIRED' ? 'APPROVAL' : verdict
}
