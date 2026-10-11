/**
 * One report's generation state, drawn as a badge (M17.9).
 *
 * The state is a fact about the *file*, not about the request that produced it:
 * `completed` means the artifact is on disk, `generating` means a row exists and
 * the bytes do not yet, and `failed` means generation was attempted and did not
 * finish. Colouring the first two as faults would be wrong — a report in flight is
 * not an error — so only `failed` is drawn in the danger shade.
 *
 * An unrecognised value is rendered as its own text in a neutral shade rather
 * than being mapped onto a known state. A backend that grows a fourth state should
 * show up on screen as itself, not as whatever it was closest to.
 */

import { C, REPORT_STATUS_COLORS, tint } from '@/lib/tokens'

/** What the badge says when the backend recorded no state at all. */
export const UNRECORDED_STATUS_TEXT = 'state not recorded'

/** One report generation state, with the sentence it means. */
const STATUS_TITLES: Readonly<Record<string, string>> = {
  completed: 'The report file was written and can be downloaded.',
  generating: 'Generation started; the file has not been written yet.',
  failed: 'Generation was attempted and did not finish. No file was produced.',
}

export function ReportStatusBadge({ status }: { status: string }) {
  const known = status !== '' && status in REPORT_STATUS_COLORS
  const color = known ? REPORT_STATUS_COLORS[status]! : C.faint
  const label = status === '' ? UNRECORDED_STATUS_TEXT : status

  return (
    <span
      className="text-xs font-medium px-2 py-0.5 rounded-full whitespace-nowrap capitalize"
      style={{ backgroundColor: tint(color, 0.12), color }}
      title={STATUS_TITLES[status] ?? 'A state this page does not recognise.'}
    >
      {label}
    </span>
  )
}
