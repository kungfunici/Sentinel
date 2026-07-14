import { NavLink } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { Activity, Radio, Monitor, Globe, GitBranch, Bell, Search, Shield, ShieldCheck } from 'lucide-react'

const links = [
  { to: '/', label: 'Dashboard', icon: Activity },
  { to: '/events', label: 'Events', icon: Bell },
  { to: '/dns', label: 'DNS', icon: Search },
  { to: '/devices', label: 'Devices', icon: Monitor },
  { to: '/blocklist', label: 'Blocklist', icon: Shield },
  { to: '/whitelist', label: 'Whitelist', icon: ShieldCheck },
  { to: '/topology', label: 'Topology', icon: GitBranch },
]

export function Sidebar() {
  return (
    <aside className="fixed left-0 top-0 bottom-0 w-56 border-r border-border-default bg-bg-primary flex flex-col z-50">
      <div className="h-14 flex items-center gap-2.5 px-5 border-b border-border-default">
        <div className="w-2.5 h-2.5 rounded-full bg-accent-cyan shadow-[0_0_8px_#00b4d8]" />
        <span className="font-mono text-sm font-semibold text-text-primary tracking-tight">Sentinel</span>
      </div>

      <nav className="flex-1 py-3 px-2 space-y-0.5">
        {links.map(l => (
          <NavLink
            key={l.to}
            to={l.to}
            end={l.to === '/'}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors',
                isActive
                  ? 'bg-accent-cyan/10 text-accent-cyan'
                  : 'text-text-secondary hover:text-text-primary hover:bg-bg-hover',
              )
            }
          >
            <l.icon size={16} />
            {l.label}
          </NavLink>
        ))}
      </nav>

      <div className="px-4 py-3 border-t border-border-default">
        <div className="flex items-center gap-2 text-[11px] text-text-muted font-mono">
          <span className="w-1.5 h-1.5 rounded-full bg-accent-green shadow-[0_0_6px_#3fb950]" />
          running
        </div>
      </div>
    </aside>
  )
}
