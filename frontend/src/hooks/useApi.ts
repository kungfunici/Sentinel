import { useState, useEffect, useCallback, useRef } from 'react'
import type { Stats, Event, DnsQuery, Device, TopologyData, LiveEvent } from '@/types/api'

const BASE = ''
const POLL_MS = 5000

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(`${BASE}${url}`)
  if (!res.ok) throw new Error(`GET ${url} ${res.status}`)
  return res.json()
}

function usePolling<T>(url: string, defaultValue: T): { data: T; loading: boolean; error: string | null } {
  const [data, setData] = useState<T>(defaultValue)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    let timer: ReturnType<typeof setTimeout>

    async function poll() {
      try {
        const d = await fetchJson<T>(url)
        if (!cancelled) { setData(d); setError(null) }
      } catch (e) {
        if (!cancelled) setError(String(e))
      } finally {
        if (!cancelled) { setLoading(false); timer = setTimeout(poll, POLL_MS) }
      }
    }

    poll()
    return () => { cancelled = true; clearTimeout(timer) }
  }, [url])

  return { data, loading, error }
}

export function useStats() {
  return usePolling<Stats>('/api/stats', {} as Stats)
}

export function useEvents(severity?: string, eventType?: string, limit = 100) {
  const params = new URLSearchParams()
  if (severity) params.set('severity', severity)
  if (eventType) params.set('type', eventType)
  params.set('limit', String(limit))
  return usePolling<Event[]>(`/api/events?${params}`, [])
}

export function useDnsQueries(blocked = false, limit = 100) {
  return usePolling<DnsQuery[]>(`/api/dns?blocked=${blocked}&limit=${limit}`, [])
}

export function useDevices(flagged = false) {
  return usePolling<Device[]>(`/api/devices?flagged=${flagged}`, [])
}

export function useTopology() {
  return usePolling<TopologyData>('/api/topology', { devices: [], connections: [] })
}

export function useBlocklist() {
  const [data, setData] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const reload = useCallback(() => {
    fetchJson<{ domains: string[] }>('/api/blocklist').then(d => { setData(d.domains); setLoading(false) }).catch(e => { setError(String(e)); setLoading(false) })
  }, [])
  useEffect(() => { reload() }, [reload])
  return { data, loading, error, reload }
}

export function useAddBlocklist() {
  return useCallback(async (domain: string) => {
    const res = await fetch('/api/blocklist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    })
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  }, [])
}

export function useRemoveBlocklist() {
  return useCallback(async (domain: string) => {
    const res = await fetch(`/api/blocklist?domain=${encodeURIComponent(domain)}`, { method: 'DELETE' })
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  }, [])
}

export function useFlagDevice() {
  return useCallback(async (ip: string, flagged: boolean) => {
    await fetch(`/api/devices/${ip}/flag${flagged ? '' : '?flagged=false'}`, { method: 'POST' })
  }, [])
}

export function useWebSocket(handler: (ev: LiveEvent) => void) {
  const wsRef = useRef<WebSocket | null>(null)
  const handlerRef = useRef(handler)
  handlerRef.current = handler

  useEffect(() => {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${protocol}//${location.host}/ws/events`)
    ws.onmessage = (e) => {
      try { handlerRef.current(JSON.parse(e.data)) } catch { /* ignore */ }
    }
    ws.onclose = () => { setTimeout(() => { /* reconnect */ }, 3000) }
    wsRef.current = ws
    return () => ws.close()
  }, [])
}
