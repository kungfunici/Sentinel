import { useState } from 'react'
import { useBlocklist, useAddBlocklist, useRemoveBlocklist } from '@/hooks/useApi'
import { Button } from '@/components/ui/button'
import { Card, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Shield, Plus, Trash2 } from 'lucide-react'

export default function Blocklist() {
  const { data: domains, loading, reload } = useBlocklist()
  const addDomain = useAddBlocklist()
  const removeDomain = useRemoveBlocklist()
  const [input, setInput] = useState('')
  const [adding, setAdding] = useState(false)
  const [error, setError] = useState('')

  async function handleAdd() {
    const domain = input.trim().toLowerCase()
    if (!domain) return
    setAdding(true)
    setError('')
    try {
      await addDomain(domain)
      setInput('')
      reload()
    } catch (e) {
      setError(String(e))
    } finally {
      setAdding(false)
    }
  }

  async function handleRemove(domain: string) {
    try {
      await removeDomain(domain)
      reload()
    } catch (e) {
      setError(String(e))
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold flex items-center gap-2">
          <Shield size={20} className="text-accent-cyan" />
          Blocklist
        </h1>
        <p className="text-sm text-text-secondary mt-0.5">
          Domains blocked by the DNS monitor
        </p>
      </div>

      <div className="flex gap-2">
        <input
          className="flex-1 h-9 px-3 rounded-md bg-bg-surface border border-border-default text-sm text-text-primary placeholder:text-text-muted outline-none focus:border-accent-cyan"
          placeholder="Add domain (e.g. malware.example.com)"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleAdd()}
        />
        <Button size="sm" onClick={handleAdd} disabled={adding || !input.trim()}>
          <Plus size={14} />
          Add
        </Button>
      </div>

      {error && <p className="text-accent-red text-xs">{error}</p>}

      <Card>
        <CardHeader>
          <CardTitle>{domains.length} blocked {domains.length === 1 ? 'domain' : 'domains'}</CardTitle>
        </CardHeader>
        <div className="space-y-0.5">
          {loading && (
            <div className="text-center py-8 text-text-muted text-sm">Loading…</div>
          )}
          {!loading && domains.length === 0 && (
            <div className="text-center py-8 text-text-muted text-sm">
              <Shield size={28} className="mx-auto mb-2 opacity-30" />
              No domains in blocklist
            </div>
          )}
          {domains.map(domain => (
            <div key={domain} className="flex items-center justify-between px-3 py-2 rounded hover:bg-bg-hover transition-colors group">
              <div className="flex items-center gap-2">
                <Badge variant="critical" className="text-[10px] px-1.5 py-0">blocked</Badge>
                <span className="font-mono text-[13px] text-text-primary">{domain}</span>
              </div>
              <Button
                size="sm"
                variant="ghost"
                className="opacity-0 group-hover:opacity-100 text-accent-red"
                onClick={() => handleRemove(domain)}
              >
                <Trash2 size={14} />
              </Button>
            </div>
          ))}
        </div>
      </Card>
    </div>
  )
}
