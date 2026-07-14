import { useState, useCallback, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Shield, Plus, Trash2 } from 'lucide-react'

type Status = 'idle' | 'loading' | 'error'

export default function Whitelist() {
  const [patterns, setPatterns] = useState<string[]>([])
  const [status, setStatus] = useState<Status>('loading')
  const [err, setErr] = useState('')
  const [input, setInput] = useState('')
  const [adding, setAdding] = useState(false)

  const load = useCallback(() => {
    setStatus('loading')
    fetch('/api/whitelist')
      .then(r => r.json())
      .then(d => { setPatterns(d.patterns ?? []); setStatus('idle') })
      .catch(e => { setErr(String(e)); setStatus('error') })
  }, [])

  useEffect(() => { load() }, [load])

  async function handleAdd() {
    const p = input.trim().toLowerCase()
    if (!p) return
    setAdding(true)
    setErr('')
    try {
      const res = await fetch('/api/whitelist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pattern: p }),
      })
      if (!res.ok) throw new Error(await res.text())
      setInput('')
      load()
    } catch (e) {
      setErr(String(e))
    } finally {
      setAdding(false)
    }
  }

  async function handleRemove(pattern: string) {
    try {
      const res = await fetch(`/api/whitelist?pattern=${encodeURIComponent(pattern)}`, { method: 'DELETE' })
      if (!res.ok) throw new Error(await res.text())
      load()
    } catch (e) {
      setErr(String(e))
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold flex items-center gap-2">
          <Shield size={20} className="text-accent-green" />
          Whitelist
        </h1>
        <p className="text-sm text-text-secondary mt-0.5">
          Host patterns that bypass HTTP keyword detection
        </p>
      </div>

      <div className="flex gap-2">
        <input
          className="flex-1 h-9 px-3 rounded-md bg-bg-surface border border-border-default text-sm text-text-primary placeholder:text-text-muted outline-none focus:border-accent-cyan"
          placeholder="Add pattern (e.g. *.example.com)"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleAdd()}
        />
        <Button size="sm" onClick={handleAdd} disabled={adding || !input.trim()}>
          <Plus size={14} />
          Add
        </Button>
      </div>

      {err && <p className="text-accent-red text-xs">{err}</p>}

      <Card>
        <CardHeader>
          <CardTitle>{patterns.length} whitelisted {patterns.length === 1 ? 'pattern' : 'patterns'}</CardTitle>
        </CardHeader>
        <div className="space-y-0.5">
          {status === 'loading' && (
            <div className="text-center py-8 text-text-muted text-sm">Loading…</div>
          )}
          {status === 'error' && (
            <div className="text-center py-8 text-accent-red text-sm">Error: {err}</div>
          )}
          {status === 'idle' && patterns.length === 0 && (
            <div className="text-center py-8 text-text-muted text-sm">
              <Shield size={28} className="mx-auto mb-2 opacity-30" />
              No whitelist patterns
            </div>
          )}
          {patterns.map(p => (
            <div key={p} className="flex items-center justify-between px-3 py-2 rounded hover:bg-bg-hover transition-colors group">
              <div className="flex items-center gap-2">
                <Badge variant="success" className="text-[10px] px-1.5 py-0">whitelisted</Badge>
                <span className="font-mono text-[13px] text-text-primary">{p}</span>
              </div>
              <Button
                size="sm"
                variant="ghost"
                className="opacity-0 group-hover:opacity-100 text-accent-red"
                onClick={() => handleRemove(p)}
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
