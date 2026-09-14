# NetWatch AI — Current Task

**Current Phase:** Base Application Implementation  
**Current Milestone:** M7 — Packet Persistence — ✅ COMPLETE  
**Status:** Complete & verified

---

# M7 Completion Summary

M7 is **complete and verified**. Packet Persistence stores normalized packet
metadata to SQLite and answers historical queries, as the final stage of the
shared M5/M6/M7/M8 pipeline.

**Delivered**

| Area | Artifact |
|------|----------|
| Mapping (M7.1/M7.2/M7.4/M7.5) | `app/persistence/mapping.py` |
| Bounded buffer (M7.9) | `app/persistence/buffer.py` |
| Batch worker + transactions (M7.6/M7.7/M7.8/M7.10/M7.11) | `app/persistence/worker.py` |
| Facade, lifecycle, counters | `app/persistence/manager.py` |
| Repository (M7.3) | `app/repositories/packet.py` |
| Retention (M7.13/M7.14) | `app/persistence/retention.py` |
| Query service (M7.15) | `app/services/packet_query.py` |
| Internal API (M7.16) | `app/api/v1/packets.py` |
| Indexes (M7.12) | `app/models/packet.py` (`source_port`, `destination_port`) |
| Pipeline / stop / shutdown (M7.17/M7.18) | `packet_pipeline.py`, `capture_manager.py`, `main.py` |
| Tests (M7.19-M7.21) | `tests/test_persistence_*.py`, `test_packet_repository.py`, `test_packet_retention.py`, `test_packet_query_service.py`, `test_packets_api.py` |
| Verification / baseline (M7.22-M7.24) | `scripts/verify_m7.py`, `scripts/benchmark_m7.py` |

**Verification**

- Full suite: **453 passed**.
- `pyright backend`: **0 errors, 0 warnings**.
- `verify_m7.py` (sample mode): 4/4 packets persisted with the expected values,
  `payload_length` NULL, and retention deleted only the expired row.
- Baseline (`--packets 100000`): map+buffer ~220k-585k packets/sec; SQLite write
  ~4.9k-6.65k packets/sec (~150-205 us/packet) — commit-bound on this disk.
  Buffer bounded at 50k rows ≈ 24.8 MiB. Not a production-capacity claim.

**Fixes applied during completion**

- `mapping.protocol_label` now falls back to the transport label when the M5
  classification is `OTHER`, so a usable label such as `QUIC` is kept.
- `worker.stop` no longer races a stray final write: draining is owned by the
  caller thread and a wedged worker is detected instead of blocking forever.
- `manager.get_last_flush_at` now reports the last flush that actually wrote
  rows, making it a meaningful "data last reached the database" diagnostic.
- The interval-flush worker test now waits on the worker's own counter instead of
  reading the shared in-memory connection while the worker writes on its thread.

---

# Current Objective

Build the Packet Persistence layer for NetWatch AI.

M5 converts raw Scapy packets into normalized packets.

M6 calculates traffic statistics from those normalized packets.

M7 will persist selected normalized packet metadata into the existing SQLite database so that NetWatch AI can retain historical packet information for investigation, analytics, reports, and future detection workflows.

The main flow becomes:

    Network
        ↓
    Scapy Capture
        ↓
    PacketProcessor
        ↓
    NormalizedPacket
        ↓
    ┌─────────────────────────────┐
    │                             │
    ↓                             ↓
Traffic Statistics          Packet Persistence
                                  ↓
                              SQLite
                                  ↓
                         Historical Packet Data

---

# M7 Development Rule

M7 is responsible only for packet persistence.

Do NOT implement:

- Threat detection
- Alerts
- Behavioral baselines
- ML
- AI
- Correlation
- Risk scoring
- Automatic blocking
- WebSockets
- Frontend integration
- External SIEM integrations
- Advanced packet analysis

Those belong to later milestones.

---

# M7.1 — Review Existing Packet Database Model

Review the existing `packets` model created in M2.

Confirm:

- Available columns
- Data types
- Nullable fields
- Foreign keys
- Existing indexes
- Timestamp representation
- Protocol representation
- Packet length representation

Do not redesign the entire database unnecessarily.

The persistence layer should remain consistent with the existing database architecture.

---

# M7.2 — Define Persistence Model Mapping

Define how:

    NormalizedPacket

maps to:

    Database Packet

Document the mapping explicitly.

Example:

    NormalizedPacket.source_ip
            ↓
    Packet.source_ip

    NormalizedPacket.destination_ip
            ↓
    Packet.destination_ip

Only persist fields that actually exist in the normalized packet.

Do not invent values.

---

# M7.3 — Packet Repository

Create a dedicated packet repository.

Suggested location:

    app/repositories/packet_repository.py

Suggested responsibilities:

    add(packet)
    add_many(packets)
    get_by_id(packet_id)
    list(...)
    count(...)
    delete_before(timestamp)

The repository should isolate database operations from packet-processing logic.

---

# M7.4 — Store Normalized Packet Metadata

Persist useful packet metadata.

At minimum, support the fields already defined by the project's packet model/database design, such as:

    timestamp
    interface
    source MAC
    destination MAC
    source IP
    destination IP
    IP version
    protocol
    source port
    destination port
    TCP flags
    packet length
    packet type

Use the exact existing model fields where applicable.

---

# M7.5 — Payload Storage Policy

Do NOT store full packet payloads by default.

Reason:

- High storage consumption
- Potentially sensitive data
- Not required for the current detection architecture
- Metadata is sufficient for the base application

If the existing database contains a payload-related field, determine whether it should remain unused in V1.

Document the decision.

---

# M7.6 — Batch Write Strategy

Do not perform a database transaction for every single packet if avoidable.

Implement controlled batch persistence.

Conceptual flow:

    Packet 1 ─┐
    Packet 2  │
    Packet 3  │
    Packet 4  ├──→ Batch Buffer
    Packet 5  │
              ┘
                  ↓
             Database Write

Support configurable values such as:

    batch size
    flush interval

The implementation must balance:

- Database overhead
- Memory usage
- Persistence latency

Do not create an unbounded buffer.

---

# M7.7 — Flush Behavior

The persistence layer must flush buffered packets when:

- Batch size is reached
- Flush interval expires
- Capture is stopped
- Application is shutting down
- Explicit flush is requested

Pending packets should not be silently lost during normal shutdown.

---

# M7.8 — Persistence Worker

Do not block packet capture unnecessarily with database writes.

Use a controlled background persistence mechanism where appropriate.

Conceptual architecture:

    Capture Worker
          ↓
    PacketProcessor
          ↓
    NormalizedPacket
          ↓
    Persistence Queue
          ↓
    Persistence Worker
          ↓
    Packet Repository
          ↓
    SQLite

The persistence worker must not interfere with packet capture lifecycle.

---

# M7.9 — Queue / Buffer Management

Use a bounded queue or equivalent controlled buffer.

Handle:

- Queue growth
- Temporary database slowdown
- Database write failure
- Shutdown with pending packets

Define behavior when the queue is full.

The system must never allow unlimited memory growth.

Do not silently discard packets without documenting and logging the chosen policy.

---

# M7.10 — Database Transactions

Batch writes should use appropriate transaction handling.

Requirements:

- Commit successful batches
- Roll back failed batches
- Avoid partially committed batches where possible
- Release database resources properly

A failed batch must not corrupt the database.

---

# M7.11 — Persistence Error Isolation

A database failure must not crash the packet-capture process.

Example:

    Capture
       ↓
    Packet Processing
       ↓
    Persistence
       ↓
    Database Error

The capture and processing pipeline should remain operational according to the chosen failure policy.

Log persistence failures clearly.

---

# M7.12 — Packet Indexes

Review and add indexes that support expected packet queries.

Potential indexed fields:

- timestamp
- source IP
- destination IP
- protocol
- source port
- destination port
- interface

Do not add indexes blindly.

Consider:

- Query usefulness
- Write overhead
- Storage cost

Use the existing database model and migration/init conventions.

---

# M7.13 — Retention Policy

Implement packet retention.

Configuration should support a configurable retention period.

Existing configuration includes:

    PACKET_RETENTION_DAYS

Use that configuration rather than hard-coding a value.

Conceptual flow:

    Current Time
        ↓
    Retention Cutoff
        ↓
    Delete packet records older than cutoff

Retention must be safe and controllable.

Do not delete recent packet records.

---

# M7.14 — Retention Cleanup

Create a controlled cleanup mechanism.

Possible approach:

    delete_before(timestamp)

The cleanup operation should:

- Run safely
- Be observable through logs
- Handle database errors
- Avoid blocking packet capture for long periods
- Be testable independently

Automatic scheduling can remain simple in the base version.

---

# M7.15 — Packet Query Service

Create a service layer for packet queries where appropriate.

It should support queries such as:

    Recent packets
    Packets by source IP
    Packets by destination IP
    Packets by protocol
    Packets by port
    Packets by time range
    Packets by interface

Keep filtering logic organized.

Do not add detection logic to packet queries.

---

# M7.16 — Packet API Preparation

The master roadmap places the complete REST API in M13.

Therefore, M7 should focus on the persistence/query service and repository.

Do NOT build the complete frontend-facing packet API yet unless an internal test endpoint is required.

If a minimal internal endpoint is temporarily created for verification, clearly document it as a development/testing endpoint.

---

# M7.17 — Integration With Packet Pipeline

Extend the current pipeline:

    Scapy
       ↓
    CaptureManager
       ↓
    PacketProcessor
       ↓
    NormalizedPacket
       ├── TrafficStatisticsManager
       ├── DeviceDiscoveryManager
       └── PacketPersistence

Persistence must operate independently from:

- Statistics
- Device discovery
- Future detection

A persistence failure must not stop the other pipeline components.

---

# M7.18 — Capture Stop / Shutdown Handling

When capture stops:

    Capture Stop
         ↓
    Stop accepting new packets
         ↓
    Flush pending packet batch
         ↓
    Commit successful writes
         ↓
    Stop persistence worker
         ↓
    Release resources

When the application shuts down:

    Application Shutdown
         ↓
    Stop capture
         ↓
    Flush persistence queue
         ↓
    Close worker/resources
         ↓
    Shutdown

Pending packets should be handled according to the documented shutdown policy.

---

# M7.19 — Tests

Create unit tests for:

### Repository

- Add packet
- Add multiple packets
- Get packet
- List packets
- Count packets
- Delete old packets

### Mapping

- NormalizedPacket → database model
- Nullable fields
- Protocol fields
- Timestamp
- Packet length

### Batch persistence

- Batch below threshold
- Batch reaches threshold
- Flush interval
- Explicit flush
- Empty flush

### Transactions

- Successful commit
- Failed batch rollback
- Database exception handling

### Queue

- Normal enqueue
- Dequeue
- Bounded behavior
- Shutdown with pending items

### Retention

- Old packets deleted
- Recent packets preserved
- Empty database
- Retention configuration

### Error isolation

- Database failure
- Persistence worker failure
- Capture remains operational

---

# M7.20 — Database Tests

Verify:

- Packets are actually persisted
- Correct values are stored
- Multiple packets are stored
- Indexes exist as intended
- Queries return expected packets
- Retention deletes only eligible packets
- Rollback works after failure

Use a test database rather than the developer's live database where practical.

---

# M7.21 — Integration Test

Run:

    CaptureManager
        ↓
    PacketProcessor
        ↓
    PacketPersistence
        ↓
    SQLite

Generate harmless authorized traffic.

Verify:

1. Packets are captured.
2. Packets are normalized.
3. Packets enter the persistence queue.
4. Batches are flushed.
5. Database rows are created.
6. Stored values match normalized packet values.
7. Capture continues successfully.
8. Statistics and device discovery continue functioning.

---

# M7.22 — Manual Verification

Perform a controlled local test.

Generate normal traffic such as:

    DNS lookup
    Web request
    Ping
    Local TCP traffic

Then verify in SQLite:

    Packet records exist
    Timestamp is correct
    Source/destination information is correct
    Protocol is correct
    Ports are correct where available
    Packet length is correct

Verify that payload data is not stored by default.

---

# M7.23 — Retention Verification

Use a controlled test database.

Insert or generate records with timestamps older than the configured retention period.

Run cleanup.

Verify:

    Old records → deleted
    Recent records → preserved

Do not test retention destructively against important development data.

---

# M7.24 — Performance Baseline

Measure:

- Packets persisted per second
- Batch size
- Average write latency
- Queue depth
- Database write overhead
- CPU usage
- Memory usage
- SQLite database growth

Test at least more than one batch size if practical.

Do not claim production-scale database throughput.

---

# M7 Completion Criteria

M7 is complete when:

- Existing Packet database model has been reviewed.
- NormalizedPacket → database mapping is defined.
- Packet repository exists.
- Normalized packet metadata can be persisted.
- Payload is not stored by default.
- Batch writes work.
- Flush behavior works.
- Persistence runs without unnecessarily blocking packet capture.
- Queue/buffer is bounded.
- Transaction handling works.
- Persistence errors are isolated.
- Appropriate packet indexes exist.
- Retention configuration works.
- Retention cleanup works.
- Packet query service works.
- Capture stop flushes pending packets.
- Application shutdown handles pending persistence work.
- Unit tests pass.
- Database tests pass.
- Integration tests pass.
- Manual verification succeeds.
- Retention verification succeeds.
- Performance baseline is recorded.

---

# Current Immediate Task — M7.1 (completed)

**M7.1 — Review the existing `packets` database model and define the NormalizedPacket → Packet persistence mapping.**

All eleven preparation steps were completed before the repository and worker were
written; the resulting mapping is the single source of truth in
`app/persistence/mapping.py`.

1. [x] Reviewed the M2 `Packet` SQLAlchemy model.
2. [x] Reviewed the M5 `NormalizedPacket` schema.
3. [x] Compared their fields.
4. [x] Identified missing mappings (interface, MACs and ip_version have no column).
5. [x] Decided the nullable fields (`source_port`, `destination_port`, `tcp_flags`).
6. [x] Confirmed timestamp representation (naive UTC `datetime` in SQLite).
7. [x] Confirmed payload is excluded (`payload_length` stays NULL, M7.5).
8. [x] Reviewed existing packet indexes and added the two port indexes (M7.12).
9. [x] Defined the repository interface (`add`, `add_many`, `write_batch`,
       `get_by_id`, `list`, `count`, `delete_before`).
10. [x] Added model/mapping tests (`tests/test_persistence_mapping.py`).
11. [x] Implemented batch persistence afterwards.

**Next milestone:** M9 — Connection Tracking.

---

# Architecture Boundary

M7 produces:

    NormalizedPacket
          ↓
    PacketPersistence
          ↓
    PacketRepository
          ↓
    SQLite

M7 provides historical packet metadata for future:

    Detection
    Device Analysis
    Connection Tracking
    Analytics
    Reports
    Investigation

M7 itself must not implement those systems.
