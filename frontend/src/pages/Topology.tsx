import { useTopology } from '@/hooks/useApi'
import { Card, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Globe } from 'lucide-react'

export default function Topology() {
  const { data, loading, error } = useTopology()

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold">Topology</h1>
        <p className="text-sm text-text-secondary mt-0.5">Network topology and traffic flows</p>
      </div>

      {error && <div className="text-accent-red text-sm">Error: {error}</div>}
      {!error && loading && <div className="text-text-secondary text-sm">Loading…</div>}

      {!error && data && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <Card>
            <CardHeader>
              <CardTitle>Devices ({data.devices.length})</CardTitle>
            </CardHeader>
            <div className="space-y-1">
              {data.devices.map(d => (
                <div key={d.ip} className="flex items-center gap-3 px-2 py-2 rounded hover:bg-bg-hover transition-colors">
                  <div className={`w-2 h-2 rounded-full ${d.is_gateway ? 'bg-accent-yellow shadow-[0_0_6px_#d29922]' : 'bg-accent-cyan'}`} />
                  <span className="font-mono text-[13px] text-accent-cyan w-36">{d.ip}</span>
                  <span className="text-text-secondary text-xs truncate flex-1">{d.vendor || d.hostname || '—'}</span>
                  {d.is_gateway && <Badge variant="warning">gateway</Badge>}
                  {d.flagged && <Badge variant="critical">flagged</Badge>}
                </div>
              ))}
              {data.devices.length === 0 && (
                <div className="text-center py-8 text-text-muted">
                  <Globe size={32} className="mx-auto mb-2 opacity-30" />
                  <div className="text-sm">No devices discovered yet</div>
                </div>
              )}
            </div>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Top Connections</CardTitle>
            </CardHeader>
            <div className="space-y-1">
              {data.connections.slice(0, 20).map((c, i) => (
                <div key={i} className="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-bg-hover transition-colors font-mono text-[13px]">
                  <span className="text-accent-cyan">{c.src_ip}</span>
                  <span className="text-text-muted">→</span>
                  <span className="text-text-secondary">{c.dst_ip}</span>
                  <span className="text-text-muted ml-auto">{c.count} pkts</span>
                </div>
              ))}
              {data.connections.length === 0 && (
                <div className="text-center py-8 text-text-muted text-sm">No connections recorded yet</div>
              )}
            </div>
          </Card>
        </div>
      )}
    </div>
  )
}
