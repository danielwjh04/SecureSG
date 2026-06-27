import { AlertFeed } from './components/AlertFeed'
import { AppHeader } from './components/AppHeader'
import { MonthlySummary } from './components/MonthlySummary'
import { SafeContentRegistry } from './components/SafeContentRegistry'
import { StatusBar } from './components/StatusBar'
import { useDashboardLive } from './hooks/useDashboardLive'

export default function App() {
  const { connected, modelState, latestContent, refreshTick } = useDashboardLive()
  return (
    <div className="app">
      <AppHeader connected={connected} />
      <StatusBar modelState={modelState} latestContent={latestContent} />
      <main className="app__main">
        <section className="app__intro" aria-labelledby="dashboard-title">
          <div>
            <p className="app__eyebrow">Security Operations</p>
            <h2 id="dashboard-title">Verified and redacted data ready for AI ingestion.</h2>
            <p>
              Monitor blocked prompts, review provenance, and keep safe content flowing
              through SecureSG's live policy screen.
            </p>
          </div>
          <div className="capacity-card">
            <span className="capacity-card__icon" aria-hidden="true">
              <span className="material-symbols-outlined">verified_user</span>
            </span>
            <div>
              <span className="capacity-card__label">Live Safe Capacity</span>
              <strong>{latestContent ? 'Active' : 'Ready'}</strong>
            </div>
          </div>
        </section>
        <div className="app__grid">
          <div className="app__wide">
            <AlertFeed refreshTick={refreshTick} />
          </div>
          <MonthlySummary refreshTick={refreshTick} />
          <SafeContentRegistry refreshTick={refreshTick} />
        </div>
      </main>
    </div>
  )
}
