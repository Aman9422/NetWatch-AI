# M15 — working notes (continuation, final state)

Everything below is the state at the end of the M15 work. The milestone record is
`docs/19_M15_Frontend_Integration.md`; this file is the short version.

---

## 1. Where M15 stands

| Item | State |
| --- | --- |
| M15.1–M15.38 (service layer, types, hooks, WebSocket layer, pages, unit tests) | green |
| M15.39 live integration suite | 64 passed (50 REST + 6 sockets + 8 pages) |
| Frontend unit suite | 422 passed (15 files) |
| `npm run typecheck` | 0 errors |
| `npm run build` | clean — 2,545 modules, JS 893.24 kB / 237.50 kB gzip |
| M15.40 manual walk | ten pages verified against the live backend |
| M15.41 feature matrix | recorded — `docs/19` §8 |
| M15.42 performance baseline | recorded — `docs/19` §11 |
| Docs | `docs/19` written; `docs/TODO.md` and `docs/Current_Task.md` updated |
| Scratch files | removed (`_tmp_mac_probe.py` and the earlier probe/output files) |

---

## 2. The question that was asked — why two devices?

The Devices page shows two records, and only one of them is this machine:

| Record | Addresses | Local | Counters |
| --- | --- | --- | --- |
| `mac:E8:BF:B8:DD:68:0A` — hostname `Aman` | 3 (`192.168.43.174` + 2 IPv6) | **yes** | sent 22,790 / received 65,931 |
| `mac:DA:2A:33:2A:B6:D8` — unnamed | **94** | no | sent 65,932 / received 22,760 |

The second is **the next hop** — the Wi-Fi AP/hotspot that owns `192.168.43.1` —
not a second computer. The evidence:

* the counters mirror each other almost exactly, which only happens if essentially
  every captured frame had two endpoints: this host and the gateway;
* its address list holds `192.168.43.1` **and** every far-end address this host
  talked to (Cloudflare `104.18.x`, Google `2001:4860::…`, Microsoft `20.x`, and
  the `64:ff9b::/96` NAT64 forms this IPv6-only cellular network synthesizes);
* `DA:2A:…` is a locally administered MAC (bit 1 of the first octet set), which is
  what an AP interface normally presents.

**Mechanism (backend, not frontend).** `app/processing/extract.py` takes each
endpoint's L2 address from the captured frame itself (`Ether.src` / `Ether.dst`),
and `app/devices/registry.py` keys a device by MAC first and then binds every IP it
sees beside that MAC (`_bind_ip`). On a routed path the frame's L2 peer *is* the
next hop, so every remote IP of off-subnet traffic lands on the gateway's record.
On a wired LAN with a router the same thing happens with the router's MAC.

`docs/12_M8_Device_Discovery_Design.md` §7 says "a device has exactly one MAC (its
identity) but many IPs" without distinguishing an L2 neighbour from a network peer.
So it is a design gap, not a bug introduced by M15 and not mock data — recorded in
`docs/19` §12 and §15, and handed back as an M8 design decision.

**Not verified anywhere in the code:** nothing in M8 or M15 marks a record as
"the next hop", so the UI cannot tell the two kinds of record apart either. If the
Devices page is to stay honest about this, that distinction has to exist on the
backend first.

---

## 3. Defects found by the manual run, and fixed

1. **CORS** — the backend allowlisted `localhost:5173` / `127.0.0.1:5173` while the
   frontend serves on `8443`, so no browser request ever reached a handler. Now a
   setting listing the ports this project serves on. Verified with a preflight and
   a request carrying `Origin`.
2. **No favicon, template title** — `404 /favicon.ico` on every load and the title
   `Figma Make App`. Now `frontend/public/favicon.svg` (the design's own mark) plus
   `title`/`icons` in `.figma/make/site.json`.
3. **`NetworkInterface` drift** — the TS model named `addresses` (never sent) and
   omitted `ip_addresses` (always sent). Now mirrors the wire.

---

## 4. Numbers worth keeping

* Run window 2026-10-06 22:22–22:29 local; capture session reported **77,441
  packets** at stop; **78,988** packet rows are stored with capture times in the
  same window — two independent counters agreeing within a couple of percent.
* Pipeline output for that run: **2 devices, 238 connections, 3 alerts, 1 incident
  (peak risk 54)**.
* `GET /dashboard/summary` 11.8 ms average over 5 calls; initial document 7.0 ms.
* Packet list held exactly **500 rows** under that traffic; dashboard ticks bounded
  at 60; packets channel rate-limited at 200 events/s (M14.16).
* Not measured: React memory under sustained streaming, alert-event render latency,
  reconnect wall-clock. Reconnect is proven as behaviour by the unit suite only.

---

## 5. Next

**M16 — Analytics**: back the remaining chart data with the real
`GET /api/v1/analytics/*` services and add time-range filtering.

Open items that are *not* M16: the M8 next-hop identity question (§2 above), and
report generation, which is M17.
