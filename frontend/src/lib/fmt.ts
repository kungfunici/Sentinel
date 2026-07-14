export function fmtEvent(type: string, data: Record<string, unknown> | string | null | undefined): string {
  const d = typeof data === 'string' ? tryJson(data) : data ?? {}

  if (type === 'packet.captured') {
    const flags = d.flags ? ` [${d.flags}]` : ''
    const port = d.dst_port ? `:${d.dst_port}` : ''
    return `${d.src_ip ?? '?'} → ${d.dst_ip ?? '?'}${port} ${d.protocol ?? ''}${flags}`
  }
  if (type === 'dns.query' || type === 'dns.blocked') {
    const blocked = d.blocked ? ' ⛔' : ''
    return `${d.src_ip ?? '?'} queried ${d.query_name ?? '?'} (${d.query_type ?? ''})${blocked}`
  }
  if (type === 'tls.handshake') {
    return `TLS ${d.src_ip ?? '?'} → ${d.dst_ip ?? '?'} SNI=${d.sni ?? '?'}`
  }
  if (type === 'device.new') {
    const mac = d.mac ? ` mac=${d.mac}` : ''
    return `New device: ${d.ip ?? '?'}${mac}`
  }
  if (type === 'port.scan_result') {
    const ports = (d.open_ports as string[] | undefined) ?? []
    return `Port scan: ${(d.description as string) ?? `${d.target as string ?? '?'} open ports: ${ports.join(', ')}`}`
  }
  if (type === 'bandwidth.report') {
    return `Bandwidth: ${(d.description as string) ?? `${d.mbps as string ?? '?'} Mbps`}`
  }

  if (d.description) return d.description as string
  try {
    return JSON.stringify(d).slice(0, 120)
  } catch {
    return String(d).slice(0, 120)
  }
}

function tryJson(s: string): Record<string, unknown> {
  try { return JSON.parse(s) } catch { return {} }
}

export function fmtEventShort(type: string): string {
  const labels: Record<string, string> = {
    'packet.captured': 'Packet',
    'dns.query': 'DNS',
    'dns.blocked': 'Blocked DNS',
    'device.new': 'New Device',
    'tls.handshake': 'TLS',
    'http.request': 'HTTP',
    'arp.anomaly': 'ARP',
    'dhcp.anomaly': 'DHCP',
    'dns.anomaly': 'DNS Anomaly',
    'icmp.anomaly': 'ICMP',
    'port.scan_result': 'Scan',
    'bandwidth.report': 'Bandwidth',
  }
  return labels[type] ?? type
}
