import type { LiveContent, ModelState } from '../hooks/useDashboardLive'
import { StatusPill } from './StatusPill'
import { Typewriter } from './Typewriter'

interface StatusBarProps {
  modelState: ModelState
  latestContent: LiveContent | null
}

export function StatusBar({ modelState, latestContent }: StatusBarProps) {
  const screening = modelState === 'screening'
  return (
    <div className={`statusbar ${screening ? 'statusbar--screening' : ''}`}>
      <span className="statusbar__state">
        <span className="statusbar__dot" />
        {screening ? 'Screening' : 'Idle'}
      </span>
      <div className="statusbar__stream">
        {latestContent ? (
          <>
            <span className="statusbar__tool">{latestContent.toolName ?? '—'}</span>
            {latestContent.verdict !== null && (
              <StatusPill verdict={latestContent.verdict} />
            )}
            <Typewriter key={latestContent.seq} text={latestContent.text} />
          </>
        ) : (
          <span className="statusbar__text faint">Awaiting traffic…</span>
        )}
      </div>
    </div>
  )
}
