/**
 * Handing a fetched file to the browser (M17.11).
 *
 * The API serves a report as a document, not as a URL: `file_path` is withheld
 * from every model (`app/schemas/report.py`), so there is no link for a page to
 * point at and no `<a href>` that could work. The bytes arrive through the normal
 * client, and this module is the one place that turns a blob into the save the
 * operator actually asked for.
 *
 * Two details are deliberate:
 *
 * * **The filename is the backend's, not a guess.** It comes from the artifact's
 *   own `Content-Disposition`, so two daily reports land as two files instead of
 *   overwriting each other as `report.pdf`.
 * * **The object URL is released.** A blob URL pins its data in memory until it is
 *   revoked, and one is created per download, so leaving it alive would leak a
 *   copy of every report the operator ever fetches. It is released a beat later
 *   rather than immediately, because a browser that is still opening the download
 *   when the URL disappears can produce an empty file.
 *
 * Nothing here is a service and nothing here talks to the backend: this is the
 * last inch of a download, and it is separated so the hook that triggers one can
 * be tested without a real browser.
 */

/** How long a blob URL is kept alive after the click that used it. */
export const OBJECT_URL_REVOKE_DELAY_MS = 1_000

/**
 * Return True when this environment can hand a file to the user.
 *
 * A test runner has no download manager, and `URL.createObjectURL` is exactly the
 * capability that is missing there. Asking first is what lets a page call
 * {@link saveBlob} unconditionally and still be told, truthfully, that nobody
 * received a file.
 */
export function canSaveFiles(): boolean {
  return (
    typeof document !== 'undefined' &&
    typeof URL !== 'undefined' &&
    typeof URL.createObjectURL === 'function'
  )
}

/**
 * Save a blob to the user's downloads, under the name the backend declared.
 *
 * The click on a synthetic anchor is the only way a browser will save bytes a
 * script holds rather than navigate to them, and the `download` attribute is what
 * makes it a save rather than a navigation to the object URL.
 *
 * @param blob The file's bytes.
 * @param filename The name to save it as, already safe (`[A-Za-z0-9-]`-ish) because
 *   it came from the artifact's own stored name.
 * @returns True when the file was handed to the browser, False when this
 *   environment cannot save files at all (a test runner, typically). The caller
 *   gets a truth value rather than silence so it can say which happened.
 */
export function saveBlob(blob: Blob, filename: string): boolean {
  if (!canSaveFiles()) return false

  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  // A synthetic link must not be followed or indexed; it exists only for the click.
  anchor.rel = 'noopener'
  anchor.style.display = 'none'
  document.body.appendChild(anchor)
  try {
    anchor.click()
  } finally {
    // The element has done its job whether or not the click threw, so it is
    // removed either way and the URL is released a beat later.
    anchor.remove()
    setTimeout(() => URL.revokeObjectURL(url), OBJECT_URL_REVOKE_DELAY_MS)
  }
  return true
}
