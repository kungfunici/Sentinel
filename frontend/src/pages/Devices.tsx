import { useState } from 'react'
import { useDevices, useFlagDevice } from '@/hooks/useApi'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'

function fmtTime(ts: number) {
  return new Date(ts * 1000).toLocaleString()
}

export default function Devices() {
  const [flaggedOnly, setFlaggedOnly] = useState(false)
  const { data: devices, loading, error } = useDevices(flaggedOnly)
  const flagDevice = useFlagDevice()
  const [flagging, setFlagging] = useState<string | null>(null)

  async function toggleFlag(ip: string, currently: boolean) {
    setFlagging(ip)
    await flagDevice(ip, !currently)
    setFlagging(null)
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold">Devices</h1>
        <p className="text-sm text-text-secondary mt-0.5">Discovered network devices</p>
      </div>

      <div className="flex gap-2">
        <Button size="sm" variant={!flaggedOnly ? 'default' : 'secondary'} onClick={() => setFlaggedOnly(false)}>
          All
        </Button>
        <Button size="sm" variant={flaggedOnly ? 'default' : 'secondary'} onClick={() => setFlaggedOnly(true)}>
          Flagged only
        </Button>
      </div>

      <Card className="p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border-default text-text-muted text-xs uppercase tracking-wider">
                <th className="text-left px-4 py-3 font-medium">IP</th>
                <th className="text-left px-4 py-3 font-medium">MAC</th>
                <th className="text-left px-4 py-3 font-medium">Hostname</th>
                <th className="text-left px-4 py-3 font-medium">Vendor</th>
                <th className="text-left px-4 py-3 font-medium">First Seen</th>
                <th className="text-left px-4 py-3 font-medium">Status</th>
                <th className="text-left px-4 py-3 font-medium">Action</th>
              </tr>
            </thead>
            <tbody>
              {error && (
                <tr><td colSpan={7} className="text-center py-8 text-accent-red">Error: {error}</td></tr>
              )}
              {!error && loading && (
                <tr><td colSpan={7} className="text-center py-8 text-text-muted">Loading…</td></tr>
              )}
              {!error && !loading && devices.length === 0 && (
                <tr><td colSpan={7} className="text-center py-8 text-text-muted">No devices</td></tr>
              )}
              {devices.map(d => (
                <tr key={d.ip} className="border-b border-border-default hover:bg-bg-hover transition-colors">
                  <td className="px-4 py-2.5 font-mono text-[13px] text-accent-cyan">{d.ip}</td>
                  <td className="px-4 py-2.5 font-mono text-[13px] text-text-secondary">{d.mac || '—'}</td>
                  <td className="px-4 py-2.5 text-text-primary">{d.hostname || '—'}</td>
                  <td className="px-4 py-2.5 text-text-secondary">{d.vendor || '—'}</td>
                  <td className="px-4 py-2.5 font-mono text-[13px] text-text-secondary whitespace-nowrap">{fmtTime(d.first_seen)}</td>
                  <td className="px-4 py-2.5">
                    {d.flagged
                      ? <Badge variant="critical">flagged</Badge>
                      : <Badge variant="success">clean</Badge>
                    }
                  </td>
                  <td className="px-4 py-2.5">
                    <Button
                      size="sm"
                      variant={d.flagged ? 'secondary' : 'outline'}
                      onClick={() => toggleFlag(d.ip, d.flagged)}
                      disabled={flagging === d.ip}
                    >
                      {d.flagged ? 'Unflag' : 'Flag'}
                    </Button>
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
