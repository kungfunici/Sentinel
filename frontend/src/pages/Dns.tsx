import { useState } from 'react'
import { useDnsQueries } from '@/hooks/useApi'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'

function fmtTime(ts: number) {
  return new Date(ts * 1000).toLocaleString()
}

export default function Dns() {
  const [blockedOnly, setBlockedOnly] = useState(false)
  const { data: queries, loading, error } = useDnsQueries(blockedOnly)

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold">DNS Queries</h1>
        <p className="text-sm text-text-secondary mt-0.5">DNS query log with blocklist filtering</p>
      </div>

      <div className="flex gap-2">
        <Button size="sm" variant={!blockedOnly ? 'default' : 'secondary'} onClick={() => setBlockedOnly(false)}>
          All
        </Button>
        <Button size="sm" variant={blockedOnly ? 'default' : 'secondary'} onClick={() => setBlockedOnly(true)}>
          Blocked only
        </Button>
      </div>

      <Card className="p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border-default text-text-muted text-xs uppercase tracking-wider">
                <th className="text-left px-4 py-3 font-medium">Time</th>
                <th className="text-left px-4 py-3 font-medium">Source</th>
                <th className="text-left px-4 py-3 font-medium">Query</th>
                <th className="text-left px-4 py-3 font-medium">Type</th>
                <th className="text-left px-4 py-3 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {error && (
                <tr><td colSpan={5} className="text-center py-8 text-accent-red">Error: {error}</td></tr>
              )}
              {!error && loading && (
                <tr><td colSpan={5} className="text-center py-8 text-text-muted">Loading…</td></tr>
              )}
              {!error && !loading && queries.length === 0 && (
                <tr><td colSpan={5} className="text-center py-8 text-text-muted">No DNS queries</td></tr>
              )}
              {queries.map(q => (
                <tr key={q.id} className="border-b border-border-default hover:bg-bg-hover transition-colors">
                  <td className="px-4 py-2.5 font-mono text-[13px] text-text-secondary whitespace-nowrap">{fmtTime(q.timestamp)}</td>
                  <td className="px-4 py-2.5 font-mono text-[13px] text-text-secondary">{q.src_ip}</td>
                  <td className="px-4 py-2.5 text-text-primary font-medium">{q.query_name}</td>
                  <td className="px-4 py-2.5 text-text-secondary">{q.query_type}</td>
                  <td className="px-4 py-2.5">
                    {q.blocked
                      ? <Badge variant="critical">BLOCKED</Badge>
                      : <Badge variant="success">allowed</Badge>
                    }
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}
