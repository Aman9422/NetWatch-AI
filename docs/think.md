# NetWatch AI — Working Notes

Scratch state, kept current. M13 — REST API is closed out.

## Where we are

M13 is complete, verified and baselined:

* full suite **1639 passed**; pyright **0 errors, 0 warnings, 0 informations**
* `backend/scripts/verify_m13.py` sample mode green (M13.36)
* `backend/scripts/benchmark_m13.py` written and run (M13.37); the figures are
  recorded in `docs/TODO.md`, and the milestone record is in
  `docs/Current_Task.md`

## The old checklist, finished

* [x] Fix envelope validation checks
* [x] Fix connections filter assertion
* [x] Fix alert transition assertion
* [x] Run `verify_m13.py` sample mode green
* [x] Write `benchmark_m13.py` (M13.37)
* [x] Update docs (TODO, Current_Task, think)
* [x] Remove temporary `backend/_inspect_routes.py`

## Details worth remembering

* The packet route's time filter is `since` / `until` (ISO-8601), not the
  `start_time` / `end_time` the milestone text sketches.
* `protocol` on `/packets` is a free-form label, so an unknown one selects
  nothing rather than being refused — while an *enumerated* filter such as
  `severity` on `/alerts` is refused with `400 INVALID_FILTER`. Those are two
  different, both-correct behaviours, and the verification asserts each.
* `GET /alerts/{id}` returns `{alert, evidence, evidence_by_type}`, so an alert's
  own fields sit one level down under `alert`.
* `GET /alerts?status=...` is ordered newest-first, so "the first row" is the
  most recent alert, not the first one created.
* The benchmark showed `/packets?destination_port=443` (24.4 ms) costing more
  than the unfiltered page (10.8 ms) over a 10,000-row store. Recorded as
  observed rather than explained; re-measure it first if the store grows.
* SQLite here lives on a OneDrive-synced path, so write-heavy figures (M7's
  writes, M11's per-alert commit) are pessimistic compared with a local disk.
  Reads are largely unaffected.
* `get_alert_queries` holds a session *factory*, not a session, which is why the
  verify and benchmark scripts override it separately from `get_db`.

## Next

M14 — WebSockets, layered on the M13 surface.
