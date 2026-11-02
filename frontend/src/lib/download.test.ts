/**
 * Handing a fetched file to the browser (M17.11, tested in M18.8).
 *
 * `src/lib/download.ts` is the last inch of a report download and had no test at
 * all, which matters more here than the file's size suggests. M18.8 asks
 * specifically that "report files are downloaded from the backend, not fabricated
 * browser URLs", and this module is the only place where a browser URL is created
 * at all — so it is the one place where that could be got wrong.
 *
 * Three claims are what these tests exist to pin:
 *
 * * **The bytes are the caller's.** `saveBlob` is handed a `Blob` and must put
 *   *that* blob behind the URL: not one rebuilt from a report id, not one fetched
 *   again, not an `<a href>` to an endpoint. The blob's identity is asserted, and so
 *   is the absence of any request.
 * * **The name is the backend's.** The `download` attribute is the artifact's own
 *   stored name, passed through exactly, so two daily reports arrive as two files
 *   rather than overwriting one another. A future "helpful" rename would fail here.
 * * **The URL is released.** An object URL pins its bytes in memory until it is
 *   revoked, and one is created per download. It must be revoked — but only after
 *   the click, because a browser still opening the file when the URL disappears
 *   writes an empty one.
 *
 * The capability under test is whether `URL.createObjectURL` exists at all, so the
 * global `URL` is replaced for each test rather than patched. That keeps the suite
 * independent of what the environment happens to implement: jsdom's own
 * `createObjectURL` refuses a `Blob` built in another realm, and whether it exists
 * changes between jsdom versions — so asserting on the environment would be
 * asserting on jsdom rather than on this module.
 */

import { afterEach, describe, expect, it, vi } from 'vitest'
import { OBJECT_URL_REVOKE_DELAY_MS, canSaveFiles, saveBlob } from '@/lib/download'

/** The object URL the stub implementations report, so assertions can name it. */
const OBJECT_URL = 'blob:netwatch/000123'

/** The object-URL methods a test installed, as spies so their use can be asserted. */
interface ObjectUrlSpies {
  readonly create: ReturnType<typeof vi.fn>
  readonly revoke: ReturnType<typeof vi.fn>
}

/**
 * Install a stand-in `URL` carrying the object-URL methods, and record their use.
 *
 * The global is replaced rather than patched, because the *existence* of
 * `createObjectURL` is the capability under test. Doing it this way also keeps the
 * suite honest about the module rather than about the environment: it works the
 * same on a jsdom that implements object URLs and one that does not.
 *
 * `unstubGlobals` is on in `vitest.config.ts`, so the real `URL` is back for the
 * next test without any cleanup here — and nothing inside a download needs the
 * global constructor: an `href` setter resolves through jsdom's own parser.
 */
function installObjectUrls(url: string = OBJECT_URL): ObjectUrlSpies {
  const create = vi.fn(() => url)
  const revoke = vi.fn()
  vi.stubGlobal('URL', { createObjectURL: create, revokeObjectURL: revoke })
  return { create, revoke }
}

/** Install a `URL` that cannot hand a file over, because it has no such method. */
function installUrlWithoutObjectUrls(): void {
  vi.stubGlobal('URL', {})
}

/**
 * `document.createElement` as the DOM defines it, captured before any spy exists.
 *
 * Held at module scope on purpose: {@link collectAnchors} may be called more than
 * once in a test, and reading `document.createElement` at call time would capture
 * the previous spy and recurse until the stack ran out.
 */
const realCreateElement = document.createElement.bind(document)

afterEach(() => {
  vi.useRealTimers()
})

/** A blob of text, as the client hands one to `saveBlob`. */
function blobOf(text: string): Blob {
  return new Blob([text], { type: 'text/csv' })
}

/**
 * Spy on element creation and collect every anchor `saveBlob` appends, in order.
 *
 * `saveBlob` builds its own element and removes it again, so it cannot be found in
 * the document afterwards: it has to be captured at the one call that creates it.
 * Nothing else about the document is touched.
 */
function collectAnchors(): HTMLAnchorElement[] {
  const created: HTMLAnchorElement[] = []
  vi.spyOn(document, 'createElement').mockImplementation((tagName: string) => {
    const element = realCreateElement(tagName)
    if (tagName === 'a') created.push(element as HTMLAnchorElement)
    return element
  })
  return created
}

/** Return the one anchor a save appended, failing clearly when it appended none. */
function onlyAnchor(created: readonly HTMLAnchorElement[]): HTMLAnchorElement {
  expect(created).toHaveLength(1)
  const anchor = created[0]
  if (anchor === undefined) throw new Error('the save appended no anchor')
  return anchor
}

/**
 * Replace the anchor click with a spy that does not navigate.
 *
 * A plain `vi.spyOn` calls through to the original, and jsdom has no download
 * manager: the real click makes it log "Not implemented: navigation to another
 * Document" once per save. Replacing the implementation removes that noise, and the
 * click's *occurrence* is what these tests are about anyway — whether a save
 * happened, and how many times — which the spy still records.
 */
function preventNavigation(): void {
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
}

// ---------------------------------------------------------------------------
// canSaveFiles: the capability, asked before it is used
// ---------------------------------------------------------------------------

describe('canSaveFiles', () => {
  it('reports that an environment with no object URLs cannot save', () => {
    // No `createObjectURL` is available, which is the case the function exists for:
    // a test runner has no download manager to hand a file to.
    installUrlWithoutObjectUrls()

    expect(canSaveFiles()).toBe(false)
  })

  it('reports that an environment with no URL at all cannot save', () => {
    // The other condition, and the one a non-DOM runner reaches.
    vi.stubGlobal('URL', undefined)

    expect(canSaveFiles()).toBe(false)
  })

  it('reports that a browser can save once the capability is present', () => {
    installObjectUrls()

    expect(canSaveFiles()).toBe(true)
  })

  it('requires a callable, not merely a property of that name', () => {
    // A partially-implemented environment must be reported as unable rather than
    // discovered halfway through a save, after the anchor exists.
    vi.stubGlobal('URL', { createObjectURL: undefined })

    expect(canSaveFiles()).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// saveBlob: the bytes, the name, and the cleanup
// ---------------------------------------------------------------------------

describe('saveBlob', () => {
  it('declines to save when the environment cannot, and touches nothing', () => {
    installUrlWithoutObjectUrls()
    const childrenBefore = document.body.childElementCount

    expect(saveBlob(blobOf('x'), 'report.csv')).toBe(false)

    // A false answer is only honest if nothing was half-done on the way to it.
    expect(document.body.childElementCount).toBe(childrenBefore)
  })

  it('puts the exact blob it was given behind the URL', () => {
    // The M18.8 property stated as an identity: a report downloaded here is a read
    // of the bytes the backend returned, not bytes this layer produced.
    const { create } = installObjectUrls()
    preventNavigation()
    const blob = blobOf('### report')

    saveBlob(blob, OBJECT_URL)

    expect(create).toHaveBeenCalledTimes(1)
    expect(create).toHaveBeenCalledWith(blob)
  })

  it('makes no request of its own', () => {
    // If this layer could fetch, a report could be assembled from something other
    // than the response the operator's request already produced.
    installObjectUrls()
    const fetchSpy = vi.fn(() => {
      throw new Error('saveBlob must not fetch anything')
    })
    vi.stubGlobal('fetch', fetchSpy)
    preventNavigation()

    saveBlob(blobOf('bytes'), 'report.csv')

    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('saves under the name the backend declared, unchanged', () => {
    // The name is the artifact's own stored name. Re-deriving it here — from the
    // report id, say — is what would collapse two reports for one day onto one
    // file, so it is passed through byte for byte.
    installObjectUrls()
    const created = collectAnchors()
    preventNavigation()
    const filename = 'netwatch-report-000123-2026-10-09-daily.csv'

    saveBlob(blobOf('bytes'), filename)

    const anchor = onlyAnchor(created)
    expect(anchor.download).toBe(filename)
    expect(anchor.getAttribute('download')).toBe(filename)
    // It points at the object URL the browser will read the bytes from, not at an
    // API route: there is no route a page could use, because `file_path` is
    // withheld from every model.
    expect(anchor.getAttribute('href')).toBe(OBJECT_URL)
  })

  it('keeps two reports apart by giving each its own name', () => {
    installObjectUrls()
    const first = collectAnchors()
    preventNavigation()
    const firstFilename = 'netwatch-report-000001-2026-10-09-daily.csv'

    saveBlob(blobOf('one'), firstFilename)

    // A second save gets its own spy and its own list, so the two names can be
    // compared without one collection overwriting the other.
    const second = collectAnchors()
    const secondFilename = 'netwatch-report-000002-2026-10-09-daily.pdf'

    saveBlob(blobOf('two'), secondFilename)

    expect(onlyAnchor(first).download).toBe(firstFilename)
    expect(onlyAnchor(second).download).toBe(secondFilename)
  })

  it('clicks a link it has hidden and cannot be followed', () => {
    installObjectUrls()
    const created = collectAnchors()
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => {})

    saveBlob(blobOf('bytes'), 'report.csv')

    const anchor = onlyAnchor(created)
    expect(click).toHaveBeenCalledTimes(1)
    expect(anchor.rel).toBe('noopener')
    expect(anchor.style.display).toBe('none')
  })

  it('leaves no link in the document afterwards', () => {
    installObjectUrls()
    preventNavigation()

    saveBlob(blobOf('bytes'), 'report.csv')

    expect(document.querySelectorAll('a')).toHaveLength(0)
    expect(document.body.childElementCount).toBe(0)
  })

  it('releases the object URL, but not before the browser can read it', () => {
    // Revoking immediately is the tempting version, and it is the one that
    // intermittently saves an empty file: the browser opens the download after the
    // click returns.
    vi.useFakeTimers()
    const { revoke } = installObjectUrls()
    preventNavigation()

    saveBlob(blobOf('bytes'), 'report.csv')

    expect(revoke).not.toHaveBeenCalled()

    vi.advanceTimersByTime(OBJECT_URL_REVOKE_DELAY_MS - 1)
    expect(revoke).not.toHaveBeenCalled()

    vi.advanceTimersByTime(1)
    expect(revoke).toHaveBeenCalledTimes(1)
    // The URL released is the one the link pointed at, so nothing else is revoked
    // by accident and this download's bytes are the ones unpinned.
    expect(revoke).toHaveBeenCalledWith(OBJECT_URL)
  })

  it('removes the link and releases the URL even when the click fails', () => {
    // Both cleanups live in a `finally`, which is the reason neither is conditional
    // on the click succeeding. The exception still reaches the caller: swallowing it
    // would report a save that did not happen.
    vi.useFakeTimers()
    const { revoke } = installObjectUrls()
    const created = collectAnchors()
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {
      throw new Error('the download manager refused')
    })

    expect(() => saveBlob(blobOf('bytes'), 'report.csv')).toThrow(
      'the download manager refused',
    )

    expect(document.querySelectorAll('a')).toHaveLength(0)
    // The anchor was removed from the document rather than left behind, which is
    // the `finally` doing its work.
    expect(onlyAnchor(created).isConnected).toBe(false)
    vi.advanceTimersByTime(OBJECT_URL_REVOKE_DELAY_MS)
    expect(revoke).toHaveBeenCalledTimes(1)
  })
})
