import { vi } from 'vitest'

type Handler = (event: unknown) => void

// jsdom has no WebSocket, so tests stub the global with this controllable fake.
export class FakeWebSocket {
  static instances: FakeWebSocket[] = []
  static readonly OPEN = 1
  static readonly CLOSED = 3

  readonly url: string
  readyState = 0
  onopen: Handler | null = null
  onclose: Handler | null = null
  onerror: Handler | null = null
  onmessage: Handler | null = null

  constructor(url: string) {
    this.url = url
    FakeWebSocket.instances.push(this)
  }

  emitOpen(): void {
    this.readyState = FakeWebSocket.OPEN
    this.onopen?.({})
  }

  emitMessage(data: unknown): void {
    this.onmessage?.({ data: JSON.stringify(data) })
  }

  emitClose(): void {
    this.readyState = FakeWebSocket.CLOSED
    this.onclose?.({})
  }

  close(): void {
    this.readyState = FakeWebSocket.CLOSED
  }
}

export function installFakeWebSocket(): void {
  FakeWebSocket.instances = []
  vi.stubGlobal('WebSocket', FakeWebSocket)
}

export function resetFakeWebSocket(): void {
  FakeWebSocket.instances = []
  vi.unstubAllGlobals()
}
