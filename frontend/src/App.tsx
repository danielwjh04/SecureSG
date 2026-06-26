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
      <main className="app__grid">
        <div className="app__wide">
          <AlertFeed refreshTick={refreshTick} />
        </div>
        <MonthlySummary refreshTick={refreshTick} />
        <SafeContentRegistry refreshTick={refreshTick} />
      </main>
    </div>
  )
}
