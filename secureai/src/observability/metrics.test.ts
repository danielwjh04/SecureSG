import { describe, expect, it, vi } from 'vitest'
import { createMetrics, type MetricsDataset } from './metrics'

describe('createMetrics', () => {
  it('is a no-op when the dataset is null', () => {
    const metrics = createMetrics(null)
    expect(() => metrics.count('scan.verdict', { labels: ['BLOCK'] })).not.toThrow()
  })

  it('writes a data point with the name + labels as blobs and a doubles count of 1', () => {
    const writeDataPoint = vi.fn()
    const dataset: MetricsDataset = { writeDataPoint }
    createMetrics(dataset).count('scan.verdict', { labels: ['BLOCK'], index: 'u1' })
    expect(writeDataPoint).toHaveBeenCalledWith({
      blobs: ['scan.verdict', 'BLOCK'],
      doubles: [1],
      indexes: ['u1'],
    })
  })

  it('omits indexes when no index is given', () => {
    const writeDataPoint = vi.fn()
    createMetrics({ writeDataPoint }).count('guard.decision')
    expect(writeDataPoint).toHaveBeenCalledWith({ blobs: ['guard.decision'], doubles: [1] })
  })

  it('swallows a writeDataPoint failure (best-effort)', () => {
    const dataset: MetricsDataset = {
      writeDataPoint: () => {
        throw new Error('analytics down')
      },
    }
    expect(() => createMetrics(dataset).count('x')).not.toThrow()
  })
})
