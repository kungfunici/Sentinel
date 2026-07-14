import { useStats, useWebSocket } from '@/hooks/useApi'
import { Card, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Activity, Radio, Shield, Monitor } from 'lucide-react'
import { useState } from 'react'
import type { LiveEvent } from '@/types/api'
import { fmtEvent, fmtEventShort } from '@/lib/fmt'

const iconMap: Record<string, React.ReactNode> = {
  events: <Activity size={20} />,
  dns_queries: <Radio size={20} />,
  dns_blocked: <Shield size={20} />,
  packets: <Radio size={20} />,
  devices: <Monitor size={20} />,
}

const labelMap: Record<string, string> = {
  events: 'Events',
  dns_queries: 'DNS Queries',
  dns_blocked: 'Blocked',
  packets: 'Packets',
  devices: 'Devices',
}

const descMap: Record<string, string> = {
  events: 'All security events',
  dns_queries: 'All DNS queries seen',
  dns_blocked: 'Queries blocked by blocklist',
  packets: 'Raw packets captured',
  devices: 'Unique hosts discovered',
}

function StatCard({ statKey, value }: { statKey: string; value: number }) {
  const isBad = statKey === 'dns_blocked' && value > 0
  return (
    <Card className="flex items-center gap-3">
      <div className={`p-2.5 rounded-lg ${isBad ? 'bg-accent-red/10 text-accent-red' : 'bg-accent-cyan/10 text-accent-cyan'}`}>
        {iconMap[statKey] || <Activity size={20} />}
      </div>
      <div className="flex-1">
        <div className="text-xs text-text-secondary font-medium">{labelMap[statKey] || statKey}</div>
        <div className={`text-xl font-semibold font-mono ${isBad ? 'text-accent-red' : 'text-text-primary'}`}>
          {value.toLocaleString()}
        </div>
      </div>
      <div className="text-[11px] text-text-muted max-w-28 text-right leading-tight">{descMap[statKey]}</div>
    </Card>
  )
}

export default function Dashboard() {
  const { data: stats, loading, error } = useStats()
  const [live, setLive] = useState<LiveEvent[]>([])

  useWebSocket((ev) => {
    setLive(prev => [ev, ...prev].slice(0, 50))
  })

  if (error) return <div className="text-accent-red text-sm">Error: {error}</div>
  if (loading) return <div className="text-text-secondary text-sm">Loading…</div>

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Dashboard</h1>
        <p className="text-sm text-text-secondary mt-0.5">Live network security overview</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
        {stats && Object.keys(labelMap).map(k => (
          <StatCard key={k} statKey={k} value={stats[k] ?? 0} />
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Live Feed</CardTitle>
        </CardHeader>
        <div className="space-y-1 max-h-[500px] overflow-y-auto text-[13px]">
          {live.length === 0 && (
            <div className="text-text-muted text-center py-8 text-sm">Waiting for events…</div>
          )}
          {live.map((ev, i) => (
            <div key={i} className="flex items-start gap-2 px-2 py-1.5 rounded hover:bg-bg-hover transition-colors">
              <span className="text-text-muted font-mono w-16 shrink-0 pt-0.5">
                {new Date(ev.timestamp * 1000).toLocaleTimeString()}
              </span>
              <Badge variant={ev.severity as 'info' | 'warning' | 'critical'} className="shrink-0 mt-0.5">{ev.severity}</Badge>
              <span className="text-text-muted shrink-0 min-w-[80px] text-xs pt-1">{fmtEventShort(ev.type)}</span>
              <span className="text-text-secondary truncate pt-1">{fmtEvent(ev.type, ev.data)}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  )
}
