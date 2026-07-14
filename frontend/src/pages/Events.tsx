import { useState } from 'react'
import { useEvents } from '@/hooks/useApi'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'

const severities = ['all', 'info', 'warning', 'critical'] as const

function fmtTime(ts: number) {
  return new Date(ts * 1000).toLocaleString()
}

function fmtData(raw: string) {
  try {
    const d = JSON.parse(raw)
    if (d.description) return d.description
    if (d.src_ip && d.dst_ip) return `${d.src_ip} → ${d.dst_ip}${d.dst_port ? ':' + d.dst_port : ''}`
    if (d.query_name) return `${d.src_ip || '?'} queried ${d.query_name}`
    return JSON.stringify(d).slice(0, 120)
  } catch {
    return raw.slice(0, 120)
  }
}

export default function Events() {
  const [severity, setSeverity] = useState<string>('all')
  const { data: events, loading, error } = useEvents(severity !== 'all' ? severity : undefined)

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold">Events</h1>
        <p className="text-sm text-text-secondary mt-0.5">All security events</p>
      </div>

      <div className="flex gap-2">
        {severities.map(s => (
          <Button key={s} size="sm" variant={s === severity ? 'default' : 'secondary'} onClick={() => setSeverity(s)}>
            {s.charAt(0).toUpperCase() + s.slice(1)}
          </Button>
        ))}
      </div>

      <Card className="p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border-default text-text-muted text-xs uppercase tracking-wider">
                <th className="text-left px-4 py-3 font-medium">Time</th>
                <th className="text-left px-4 py-3 font-medium">Severity</th>
                <th className="text-left px-4 py-3 font-medium">Type</th>
                <th className="text-left px-4 py-3 font-medium">Source</th>
                <th className="text-left px-4 py-3 font-medium">Detail</th>
              </tr>
            </thead>
            <tbody>
              {error && (
                <tr><td colSpan={5} className="text-center py-8 text-accent-red">Error: {error}</td></tr>
              )}
              {!error && loading && (
                <tr><td colSpan={5} className="text-center py-8 text-text-muted">Loading…</td></tr>
              )}
              {!error && !loading && events.length === 0 && (
                <tr><td colSpan={5} className="text-center py-8 text-text-muted">No events</td></tr>
              )}
              {events.map(e => (
                <tr key={e.id} className="border-b border-border-default hover:bg-bg-hover transition-colors">
                  <td className="px-4 py-2.5 font-mono text-[13px] text-text-secondary whitespace-nowrap">{fmtTime(e.timestamp)}</td>
                  <td className="px-4 py-2.5"><Badge variant={e.severity as 'info' | 'warning' | 'critical'}>{e.severity}</Badge></td>
                  <td className="px-4 py-2.5 font-mono text-[13px] text-accent-cyan">{e.type}</td>
                  <td className="px-4 py-2.5 text-text-secondary">{e.source}</td>
                  <td className="px-4 py-2.5 text-text-secondary truncate max-w-xs">{fmtData(e.data)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}
