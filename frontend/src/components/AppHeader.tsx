import { useState } from 'react'
import { ApiError } from '../api/client'
import { runAttackDemo } from '../demo/runAttackDemo'

export function AppHeader({ connected }: { connected: boolean }) {
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const run = async (): Promise<void> => {
    setRunning(true)
    setError(null)
    try {
      await runAttackDemo()
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'demo failed')
    } finally {
      setRunning(false)
    }
  }

  return (
    <header className="header">
      <div className="header__brand">
        <span className="header__mark material-symbols-outlined" aria-hidden="true">
          security
        </span>
        <h1>SecureSG</h1>
        <span className="tag">Pro</span>
      </div>
      <nav className="header__nav" aria-label="Primary">
        <a href="#dashboard" className="header__link">
          Dashboard
        </a>
        <a href="#alerts" className="header__link">
          Audit Logs
        </a>
        <a href="#safe-content" className="header__link header__link--active">
          Safe Content
        </a>
        <a href="#policy" className="header__link">
          Policy Warden
        </a>
      </nav>
      <div className="header__right">
        {error !== null && <span className="header__error">{error}</span>}
        <span className={`conn ${connected ? 'conn--on' : ''}`}>
          <span className="conn__dot" />
          {connected ? 'Live' : 'Offline'}
        </span>
        <button className="btn" onClick={() => void run()} disabled={running}>
          {running ? 'Running demo…' : 'Run Attack Demo'}
        </button>
      </div>
    </header>
  )
}
