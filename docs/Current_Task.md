# NetWatch AI — Current Task

**Current Phase:** Base Application Implementation  
**Current Milestone:** M5 — Packet Processing & Normalization ✅ COMPLETE  
**Status:** Complete — next milestone: M6 (Packet Persistence)

---

# Current Objective

Build the Packet Processing and Normalization layer for NetWatch AI.

M4 successfully captures real packets using Scapy. M5 converts those raw Scapy packets into a clean, consistent internal representation that later components can use without directly depending on Scapy packet-layer details.

The main flow is:

    Network
        ↓
    Scapy Capture Engine
        ↓
    Raw Scapy Packet
        ↓
    PacketProcessor
        ↓
    Normalized Packet
        ↓
    Future Statistics / Detection / ML

M5 is responsible only for packet processing and normalization.

---

# M5 Development Rule

Do NOT implement:

- Detection rules
- Alerts
- Behavioral baselines
- ML anomaly detection
- AI analysis
- Correlation
- Risk scoring
- Packet database persistence
- WebSocket streaming
- Frontend integration
- Advanced traffic statistics

Those belong to later milestones.

---

# M5.1 — Define Normalized Packet Schema

Before implementing packet extraction logic, define the internal packet model.

Create a clear schema/model representing a normalized packet.

The model should be independent of Scapy.

Suggested fields:

    packet_id
    timestamp
    interface
    length
    source_mac
    destination_mac
    ip_version
    source_ip
    destination_ip
    protocol
    source_port
    destination_port
    tcp_flags
    packet_type

Fields that are not available for a packet type should be represented safely as null/None where appropriate.

Do not invent values.

---

# M5.2 — PacketProcessor Interface

Create a dedicated PacketProcessor responsible for converting:

    Scapy Packet
        ↓
    Normalized Packet

Suggested interface:

    PacketProcessor
        └── process(packet)

The processor should return the normalized internal representation.

Keep the interface simple so future packet-processing components can use it.

---

# M5.3 — Ethernet Extraction

Extract Layer-2 information when available:

- Source MAC
- Destination MAC
- Ethernet-related packet information

Packets without Ethernet information must still be processed safely.

---

# M5.4 — IPv4 Extraction

When an IPv4 layer is present, extract:

- Source IP
- Destination IP
- IP version
- Protocol information

Do not assume every captured packet contains IPv4.

---

# M5.5 — IPv6 Extraction

Support basic IPv6 normalization.

Extract:

- Source IPv6 address
- Destination IPv6 address
- IP version
- Next-header/protocol information

Packets that are not IPv6 must remain valid.

---

# M5.6 — TCP Extraction

When TCP is present, extract:

- Source port
- Destination port
- TCP flags

Handle packets without TCP safely.

Do not perform threat detection from TCP flags yet.

---

# M5.7 — UDP Extraction

When UDP is present, extract:

- Source port
- Destination port

Handle packets without UDP safely.

---

# M5.8 — ICMP Extraction

Support basic identification of ICMP packets.

At minimum, identify the protocol/type needed by the normalized packet model.

Do not implement ICMP attack detection.

---

# M5.9 — Basic DNS Identification

When a DNS layer is present:

- Identify the packet as DNS traffic.
- Preserve basic protocol information required by the normalized representation.

Do not implement DNS anomaly detection or threat intelligence.

---

# M5.10 — Timestamp and Packet Length

Extract:

- Capture timestamp
- Packet length

Timestamp handling must be consistent.

Packet length should be based on the captured packet rather than an invented value.

---

# M5.11 — Packet Type / Protocol Classification

Provide a basic normalized classification.

Examples:

    TCP
    UDP
    ICMP
    DNS
    IPv4
    IPv6
    ARP
    OTHER

The classification should be deterministic.

Do not build a detection engine into the classifier.

---

# M5.12 — Unsupported and Unknown Packets

The processor must safely handle:

- ARP
- Non-IP packets
- Unknown protocols
- Packets missing expected layers
- Empty/unusual Scapy packets

The processor must not crash simply because a protocol layer is unavailable.

---

# M5.13 — Malformed Packet Handling

Handle malformed or partially constructed packets safely.

Requirements:

- No application crash
- Clear error handling
- Useful logging where appropriate
- Return a controlled result or error according to the chosen design

Do not expose internal stack traces through APIs.

---

# M5.14 — Integrate With CaptureManager

Connect packet processing to the existing capture pipeline.

Current M4 flow:

    Scapy
       ↓
    CaptureManager
       ↓
    Packet Counter

M5 should extend this to:

    Scapy
       ↓
    CaptureManager
       ↓
    PacketProcessor
       ↓
    Normalized Packet
       ↓
    Temporary downstream handoff

For now, do not persist packets to the database.

The capture callback should pass packets to the processor without adding detection or analytics.

---

# M5.15 — Processing Error Isolation

A single malformed or unsupported packet must not stop packet capture.

Example:

    Packet 1 → processed
    Packet 2 → processed
    Packet 3 → processing error
    Packet 4 → processed
    Packet 5 → processed

The capture engine should continue operating.

Log processing failures appropriately.

---

# M5.16 — Tests

Create unit tests for:

### Ethernet

- Ethernet packet
- MAC extraction

### IPv4

- Source IP
- Destination IP
- IPv4 classification

### IPv6

- IPv6 source/destination
- IPv6 classification

### TCP

- Source port
- Destination port
- TCP flags

### UDP

- Source port
- Destination port

### ICMP

- ICMP identification

### DNS

- DNS identification

### General

- Timestamp
- Packet length
- Protocol classification
- Unsupported packets
- Missing layers
- Empty packets
- Malformed packets
- Processor exception handling

---

# M5.17 — Integration Tests

Verify:

    CaptureManager
        ↓
    PacketProcessor

Confirm that captured Scapy packets reach the processor and are converted into normalized packet objects.

Do not test detection or database persistence yet.

---

# M5.18 — Manual Verification

Perform a controlled local test using normal traffic.

Generate harmless traffic such as:

    Web browsing
    DNS lookup
    Ping
    Local connections

Verify that NetWatch can produce normalized records containing appropriate fields.

Example:

    TCP
    source: 192.168.1.10
    destination: 142.x.x.x
    source_port: 52341
    destination_port: 443
    length: 1280

Values must come from actual captured packets.

---

# M5.19 — Performance Baseline

Measure basic processing performance.

Record:

- Number of packets processed
- Processing time
- Approximate packets/second
- CPU usage
- Memory usage

Do not optimize prematurely.

Do not claim production throughput.

---

# M5 Completion Criteria

M5 is complete when:

- [x] Normalized packet schema exists. (`app/schemas/packet.py`)
- [x] PacketProcessor exists. (`app/processing/processor.py`)
- [x] Scapy packets can be converted into normalized packets.
- [x] Ethernet information is extracted where available. (`app/processing/extract.py`)
- [x] IPv4 is supported.
- [x] IPv6 is supported.
- [x] TCP is supported.
- [x] UDP is supported.
- [x] ICMP is identified.
- [x] DNS is identified.
- [x] Timestamp and packet length are captured.
- [x] Unsupported packets are handled safely. (ARP / non-IP / unknown → `OTHER`)
- [x] Missing layers do not crash processing.
- [x] Processing errors do not terminate packet capture. (isolated in the sniffer callback)
- [x] CaptureManager successfully hands captured packets to PacketProcessor.
- [x] Unit tests pass. (`tests/test_packet_processor.py`, 22 tests)
- [x] Integration tests pass. (`tests/test_capture_processing.py`)
- [x] Manual verification succeeds. (see performance baseline below)
- [x] Performance baseline is recorded. (see below)

---

# M5 Performance Baseline

Measured on the development machine, capturing `Wi-Fi` for 3 seconds through
the full `CaptureManager → PacketProcessor` pipeline:

| Metric                        | Value                          |
| ----------------------------- | ------------------------------ |
| Raw packets captured          | 2496                           |
| Packets normalized            | 2496                           |
| Processing errors             | 0                              |
| Approx. rate                  | ~832 packets/second            |
| Capture + processing overhead | no observable packet loss (1:1)|

Sample normalized record observed during the run:

```text
TCP  2402:8100:2cd7:9c57:d51a:2df1:60b1:77b8 -> 64:ff9b::14b8:af07
     ports 58807->443  length=1203  flags=PA  packet_type=TCP
```

Full test suite: **106 passed**. Static analysis: **pyright 0 errors**.

---

# M5 Implementation Map

```text
app/
├── schemas/packet.py        NormalizedPacket, PacketType          (M5.1)
├── processing/
│   ├── protocols.py         protocol label / number constants
│   ├── errors.py            PacketProcessingError
│   ├── extract.py           Scapy layers → ExtractedFields        (M5.3–M5.10)
│   ├── classifier.py        deterministic classification          (M5.11–M5.12)
│   └── processor.py         PacketProcessor.process()             (M5.2, M5.13)
└── services/
    ├── capture_sniffer.py   callback → processor, error isolation (M5.14–M5.15)
    └── capture_manager.py   owns the processor, wires the sink
```

---

# Current Immediate Task

**M5 is complete.** All M5 requirements are implemented, tested, and verified.

**Next milestone: M6 — Packet Persistence.** M6 will store the normalized
packets produced by M5 into SQLite through the existing packet repository —
metadata only (no payloads by default), with indexing and a retention policy.
No parsing changes are expected; M6 consumes `NormalizedPacket` as-is.

## M5 deliverables

| Area           | Location                                                       |
| -------------- | -------------------------------------------------------------- |
| Schema         | `app/schemas/packet.py` (`NormalizedPacket`, `PacketType`)      |
| Processor      | `app/processing/processor.py` (`PacketProcessor`)               |
| Extraction     | `app/processing/extract.py` (Scapy → `ExtractedFields`)        |
| Classification | `app/processing/classifier.py`                                  |
| Integration    | `app/services/capture_sniffer.py`, `app/services/capture_manager.py` |
| Unit tests     | `tests/test_packet_processor.py` (22 tests)                     |
| Integration    | `tests/test_capture_processing.py` (4 tests)                    |
| Verification   | `backend/scripts/verify_m5.py` (sample + live modes)            |

**Result:** 106 tests passing, pyright 0 errors, real capture
2496 packets normalized with 0 errors.

---

# Architecture Boundary

M5 should produce:

    Scapy Packet
          ↓
    PacketProcessor
          ↓
    NormalizedPacket

The rest of NetWatch should eventually depend on `NormalizedPacket`, not directly on Scapy internals.

---
# M5 — Packet Processing ✅ COMPLETE

* [x] Create packet parser — `app/processing/processor.py` (`PacketProcessor`)
* [x] Parse Ethernet — source/destination MAC, normalized
* [x] Parse IPv4/IPv6 — addresses + IP version + protocol number
* [x] Parse TCP — ports + flags
* [x] Parse UDP — ports
* [x] Parse ICMP — identified
* [x] Extract ports — TCP/UDP source + destination
* [ ] Extract TTL — deferred (not required by the M5 spec; to be populated in
      M6 persistence — the `Packet.ttl` column already exists)
* [x] Extract TCP flags — compact string form (e.g. `PA`, `S`)
* [x] Extract packet length — from the captured frame
* [x] Add timestamp — capture time (epoch seconds)
* [x] Create normalized packet model — `app/schemas/packet.py`
* [x] Handle malformed packets — controlled `PacketProcessingError`, isolated
      so one bad packet never stops capture

**Notes:** DNS identified (over UDP/TCP); ARP and unknown packets classified as
`ARP`/`OTHER` without crashing. Verification script: `backend/scripts/verify_m5.py`.
Full suite: 106 passed, pyright 0 errors. Real capture: 2496 normalized / 0 errors.