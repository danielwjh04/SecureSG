import { useEffect, useReducer } from 'react'
import type { DashboardEvent } from '../api/types'
import { useDebouncedValue } from './useDebouncedValue'

export type ModelState = 'idle' | 'screening'

export interface LiveContent {
  seq: number
  text: string
  verdict: string | null
  toolName: string | null
}

export interface LiveState {
  connected: boolean
  modelState: ModelState
  latestContent: LiveContent | null
  eventSeq: number
}

export type LiveAction =
  | { type: 'open' }
  | { type: 'close' }
  | { type: 'event'; event: DashboardEvent }

export const initialLiveState: LiveState = {
  connected: false,
  modelState: 'idle',
  latestContent: null,
  eventSeq: 0,
}

// Pure reducer (exported for tests). VERDICT and CONTENT bump eventSeq — the
// refetch signal — while MODEL_STATE and CONTENT also feed the live status bar.
export function dashboardReducer(state: LiveState, action: LiveAction): LiveState {
  switch (action.type) {
    case 'open':
      return { ...state, connected: true }
    case 'close':
      return { ...state, connected: false }
    case 'event': {
      const { event } = action
      if (event.kind === 'MODEL_STATE') {
        const modelState: ModelState =
          event.model_state === 'screening' ? 'screening' : 'idle'
        return { ...state, modelState }
      }
      const eventSeq = state.eventSeq + 1
      if (event.kind === 'CONTENT') {
        return {
          ...state,
          eventSeq,
          latestContent: {
            seq: eventSeq,
            text: event.content ?? '',
            verdict: event.verdict,
            toolName: event.tool_name,
          },
        }
      }
      return { ...state, eventSeq }
    }
  }
}

const KINDS = new Set<DashboardEvent['kind']>(['VERDICT', 'CONTENT', 'MODEL_STATE'])

function isDashboardEvent(value: unknown): value is DashboardEvent {
  if (typeof value !== 'object' || value === null || !('kind' in value)) return false
  return KINDS.has((value as { kind: DashboardEvent['kind'] }).kind)
}

function socketUrl(): string {
  const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws'
  return `${scheme}://${window.location.host}/dashboard/ws`
}

export interface DashboardLive {
  connected: boolean
  modelState: ModelState
  latestContent: LiveContent | null
  refreshTick: number
}

const BASE_BACKOFF_MS = 500
const MAX_BACKOFF_MS = 10000

export function useDashboardLive(): DashboardLive {
  const [state, dispatch] = useReducer(dashboardReducer, initialLiveState)
  const refreshTick = useDebouncedValue(state.eventSeq, 200)

  useEffect(() => {
    let closedByUs = false
    let backoff = BASE_BACKOFF_MS
    let socket: WebSocket | null = null
    let reconnectTimer: ReturnType<typeof setTimeout> | undefined

    const connect = (): void => {
      socket = new WebSocket(socketUrl())
      socket.onopen = () => {
        backoff = BASE_BACKOFF_MS
        dispatch({ type: 'open' })
      }
      socket.onmessage = (message: MessageEvent) => {
        try {
          const parsed: unknown = JSON.parse(message.data as string)
          if (isDashboardEvent(parsed)) dispatch({ type: 'event', event: parsed })
        } catch {
          // ignore malformed frames
        }
      }
      socket.onclose = () => {
        if (closedByUs) return
        dispatch({ type: 'close' })
        const jitter = Math.floor(Math.random() * BASE_BACKOFF_MS)
        reconnectTimer = setTimeout(connect, backoff + jitter)
        backoff = Math.min(backoff * 2, MAX_BACKOFF_MS)
      }
      socket.onerror = () => socket?.close()
    }

    connect()

    return () => {
      closedByUs = true
      if (reconnectTimer !== undefined) clearTimeout(reconnectTimer)
      socket?.close()
    }
  }, [])

  return {
    connected: state.connected,
    modelState: state.modelState,
    latestContent: state.latestContent,
    refreshTick,
  }
}
