/**
 * The Figma Make palette, named once (M15.2).
 *
 * Every page in the original design declared its own copy of this object. New
 * and integrated components import it instead, so the visual baseline is defined
 * in one place and a change to a shade reaches the whole application. The values
 * are exactly the originals — this module is a lift-and-share, not a redesign
 * (M15.2).
 *
 * Nothing here is a semantic role. The names are the colours the design uses, and
 * a component picks the one its meaning calls for; a "danger" band is red because
 * the design says so, not because a theme maps it.
 */

/** The shared colour tokens. */
export const C = {
  accent: '#38BDF8',
  success: '#22C55E',
  warning: '#F59E0B',
  danger: '#EF4444',
  info: '#06B6D4',
  purple: '#818CF8',
  orange: '#F97316',
  bg: '#020617',
  card: '#1E293B',
  panel: '#0F172A',
  border: '#334155',
  text: '#F8FAFC',
  muted: '#94A3B8',
  faint: '#64748B',
  dim: '#475569',
} as const

/** One colour token. */
export type TokenName = keyof typeof C

/** The Recharts tooltip style the design uses on every chart. */
export const TIP = {
  backgroundColor: C.panel,
  border: `1px solid ${C.border}`,
  borderRadius: '10px',
  fontSize: '12px',
  fontFamily: 'Inter',
  color: C.text,
} as const

/** A translucent tint of a token, for a badge or a filled icon tile. */
export function tint(color: string, alpha: number): string {
  // The design expresses tints as 8-digit hex, e.g. `${accent}15`. This keeps
  // that spelling in one place so a caller does not hand-write the suffix.
  const clamped = Math.max(0, Math.min(1, alpha))
  const byte = Math.round(clamped * 255)
  return `${color}${byte.toString(16).padStart(2, '0')}`
}

/** The four alert severities, mapped to the colour the design gives each. */
export const SEVERITY_COLORS: Readonly<Record<string, string>> = {
  critical: C.danger,
  high: C.orange,
  medium: C.warning,
  low: C.info,
}

/** The five alert lifecycle states, mapped to a colour the design uses. */
export const ALERT_STATUS_COLORS: Readonly<Record<string, string>> = {
  open: C.danger,
  acknowledged: C.info,
  resolved: C.success,
  dismissed: C.dim,
  false_positive: C.purple,
}

/** The four incident states, mapped to a colour the design uses. */
export const INCIDENT_STATUS_COLORS: Readonly<Record<string, string>> = {
  open: C.danger,
  investigating: C.warning,
  resolved: C.success,
  dismissed: C.dim,
}

/** The four risk bands, mapped to a colour the design uses. */
export const RISK_BAND_COLORS: Readonly<Record<string, string>> = {
  minimal: C.success,
  low: C.info,
  moderate: C.warning,
  high: C.danger,
}

/** M8 device activity states, mapped to a colour the design uses. */
export const DEVICE_STATUS_COLORS: Readonly<Record<string, string>> = {
  online: C.success,
  active: C.success,
  idle: C.warning,
  offline: C.dim,
  inactive: C.dim,
}

/**
 * M17 report generation states, mapped to a colour the design uses.
 *
 * `failed` is the only one that is a fault and the only one drawn in the danger
 * shade; `generating` is amber because the work is genuinely in flight rather
 * than because anything is wrong. An unrecognised state falls through to a
 * neutral shade rather than being coloured as though it were understood.
 */
export const REPORT_STATUS_COLORS: Readonly<Record<string, string>> = {
  completed: C.success,
  generating: C.warning,
  failed: C.danger,
}
