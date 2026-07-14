import * as React from 'react'
import { cn } from '@/lib/utils'

const variants = {
  default: 'bg-accent-cyan text-white hover:bg-accent-cyan-dim',
  secondary: 'bg-bg-surface text-text-primary border border-border-default hover:bg-bg-hover',
  ghost: 'text-text-secondary hover:text-text-primary hover:bg-bg-hover',
  outline: 'border border-border-default bg-transparent hover:bg-bg-hover text-text-primary',
  danger: 'bg-accent-red text-white hover:opacity-90',
}

type Variant = keyof typeof variants
type Size = 'sm' | 'md' | 'icon'

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  size?: Size
}

export function Button({ className, variant = 'default', size = 'md', ...props }: ButtonProps) {
  const sizeClasses: Record<Size, string> = {
    sm: 'h-7 px-2.5 text-xs',
    md: 'h-9 px-4 text-sm',
    icon: 'h-9 w-9',
  }
  return (
    <button
      className={cn(
        'inline-flex items-center justify-center gap-2 rounded-md font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-accent-cyan/50 disabled:opacity-50 disabled:pointer-events-none cursor-pointer',
        variants[variant],
        sizeClasses[size],
        className,
      )}
      {...props}
    />
  )
}
