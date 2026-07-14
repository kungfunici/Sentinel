export interface Event {
  id: number
  timestamp: number
  severity: 'info' | 'warning' | 'critical'
  type: string
  source: string
  data: string
}

export interface DnsQuery {
  id: number
  timestamp: number
  src_ip: string
  query_name: string
  query_type: string
  blocked: boolean
}

export interface Device {
  ip: string
  mac: string | null
  hostname: string | null
  vendor: string | null
  first_seen: number
  last_seen: number
  flagged: boolean
}

export interface Stats {
  events: number
  dns_queries: number
  dns_blocked: number
  packets: number
  devices: number
  [key: string]: number
}

export interface TopologyData {
  devices: (Device & { is_gateway: boolean })[]
  connections: { src_ip: string; dst_ip: string; count: number }[]
}

export interface LiveEvent {
  type: string
  severity: 'info' | 'warning' | 'critical'
  source: string
  timestamp: number
  data: Record<string, unknown>
}
