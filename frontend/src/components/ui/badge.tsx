import { cn } from '@/lib/utils'

interface BadgeProps {
  children: React.ReactNode
  variant?: 'info' | 'warning' | 'critical' | 'success' | 'neutral'
  className?: string
}

const map: Record<string, string> = {
  info: 'bg-accent-cyan/15 text-accent-cyan border-accent-cyan/30',
  warning: 'bg-accent-yellow/15 text-accent-yellow border-accent-yellow/30',
  critical: 'bg-accent-red/15 text-accent-red border-accent-red/30',
  success: 'bg-accent-green/15 text-accent-green border-accent-green/30',
  neutral: 'bg-bg-hover text-text-secondary border-border-default',
}

export function Badge({ children, variant = 'neutral', className }: BadgeProps) {
  return (
    <span className={cn('inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium border', map[variant], className)}>
      {children}
    </span>
  )
}
