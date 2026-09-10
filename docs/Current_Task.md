# M4 — Packet Capture Engine

Update `Current_Task.md` to the following. M4 is the first milestone where NetWatch AI will interact with **real network traffic**, so we should keep it isolated from packet parsing, detection, ML, and AI until the capture layer is stable.

````markdown
# NetWatch AI — Current Task

**Current Phase:** Base Application Implementation  
**Current Milestone:** M4 — Packet Capture Engine  
**Status:** In Progress

---

# Current Objective

Build the Packet Capture Engine required by NetWatch AI.

The objective of M4 is to:

- Use the interface selected by M3.
- Capture real network packets using Scapy.
- Start and stop packet capture safely.
- Maintain capture state.
- Count captured packets.
- Handle capture errors.
- Prevent duplicate capture sessions.
- Keep packet capture independent from packet parsing and detection.

**Packet parsing will be implemented in M5.**

---

# M4 — Packet Capture Engine

## M4.1 — Scapy Dependency

- [x] Verify Scapy installation. (scapy 2.7.0)
- [x] Install Scapy if required. (installed into backend/.venv)
- [x] Add Scapy to `requirements.txt`. (`scapy>=2.6.0`)
- [x] Verify Scapy imports successfully. (`AsyncSniffer` available)
- [x] Verify Scapy can access the selected interface where permitted. (1112 packets captured in 3s on `Wi-Fi`)

---

## M4.2 — Capture Manager

Create the service responsible for controlling packet capture.

Responsibilities:

```text
CaptureManager
│
├── start()
├── stop()
├── get_status()
├── is_running()
└── get_packet_count()
````

The Capture Manager should:

* Use the interface selected by M3.
* Maintain capture state.
* Start capture in a controlled execution context.
* Stop capture safely.
* Track captured packet count.
* Prevent multiple capture sessions.
* Handle runtime errors.

The Capture Manager must not perform packet parsing or threat detection.

---

## M4.3 — Capture State

The capture engine should maintain a clear state.

Possible states:

```text
stopped
starting
running
stopping
error
```

Example:

```json
{
  "status": "running",
  "interface": "Wi-Fi",
  "packet_count": 1250
}
```

---

## M4.4 — Capture Session

Each capture run should have a clear lifecycle.

```text
Stopped
   ↓
Starting
   ↓
Running
   ↓
Stopping
   ↓
Stopped
```

If an error occurs:

```text
Running
   ↓
Error
   ↓
Stopped
```

Future versions may store persistent capture-session information.

---

## M4.5 — Packet Counter

The capture engine should maintain a packet counter.

Example:

```text
Captured Packets:
125,430
```

Requirements:

* [x] Initialize counter when capture starts.
* [x] Increment counter for each captured packet.
* [x] Return current count.
* [x] Reset appropriately for a new session.
* [x] Avoid race conditions where applicable. (access serialised behind an `RLock`)

---

## M4.6 — Start Capture

Implement controlled packet capture using Scapy.

Conceptual flow:

```text
Selected Interface
       ↓
Capture Manager
       ↓
Scapy Sniffer
       ↓
Packet Received
       ↓
Packet Counter
```

The capture callback should initially perform only the minimum work necessary.

It should not yet:

* Parse packets.
* Store packets in the database.
* Run detection rules.
* Run ML.
* Run AI.
* Send packets to the frontend.

Those responsibilities belong to later milestones.

---

## M4.7 — Stop Capture

The capture engine must support graceful shutdown.

Requirements:

* [x] Stop an active capture.
* [x] Release capture resources.
* [x] Update capture state.
* [x] Preserve final packet count.
* [x] Allow a new capture to start afterward.

---

## M4.8 — Duplicate Session Prevention

The system must prevent multiple capture sessions from running simultaneously.

Example:

```text
Capture already running
        ↓
POST /capture/start
        ↓
Reject request
```

Expected response:

```text
HTTP 409 Conflict
```

Example:

```json
{
  "success": false,
  "message": "Packet capture is already running"
}
```

---

## M4.9 — Interface Validation

Before starting capture:

```text
Capture Start Request
        ↓
Get Selected Interface
        ↓
Validate Interface
        ↓
+----------------------+
| Valid?               |
+----------+-----------+
           |
       +---+---+
       |       |
      Yes      No
       |       |
       v       v
   Start     Reject
   Capture   Request
```

The Capture Manager must not start packet capture on an invalid or unavailable interface.

---

## M4.10 — Capture API

Implement the following endpoints.

### GET

```text
GET /api/v1/capture/status
```

Returns current capture state.

Example:

```json
{
  "success": true,
  "data": {
    "status": "running",
    "interface": "Wi-Fi",
    "packet_count": 125430
  }
}
```

### POST

```text
POST /api/v1/capture/start
```

Starts packet capture using the selected interface.

### POST

```text
POST /api/v1/capture/stop
```

Stops packet capture.

These endpoints should use the Capture Manager rather than containing capture logic directly.

---

## M4.11 — Capture Configuration

The capture engine should read:

```text
Selected Interface
```

from the Interface Manager implemented in M3.

Configuration flow:

```text
M3 Interface Manager
       ↓
Selected Interface
       ↓
M4 Capture Manager
       ↓
Scapy
```

Do not duplicate interface-selection logic inside the Capture Manager.

---

## M4.12 — Threading / Execution Model

Packet capture should not block the FastAPI application.

The capture operation should execute in a controlled background execution context.

Conceptual architecture:

```text
FastAPI
   |
   +--------------------+
   |                    |
   v                    v
API Requests       Capture Worker
                        |
                        v
                     Scapy
```

The exact implementation may use a background thread or another suitable execution mechanism.

The chosen approach must allow:

* Start.
* Stop.
* State inspection.
* Packet counting.
* Exception handling.

---

## M4.13 — Thread Safety

Shared capture state may be accessed by:

* FastAPI request handlers.
* Capture worker.
* Shutdown logic.

Protect shared mutable state where necessary.

Potential shared state:

```text
is_running
status
packet_count
selected_interface
capture_error
```

---

## M4.14 — Error Handling

The capture engine should gracefully handle:

* Invalid interface.
* Interface unavailable.
* Permission denied.
* Capture initialization failure.
* Capture runtime failure.
* Stop failure.
* Unexpected worker termination.

Example:

```json
{
  "success": false,
  "message": "Unable to start packet capture"
}
```

Internal error details should be logged rather than exposed unnecessarily to the client.

---

## M4.15 — Logging

Log important capture events.

### Start

```text
Packet capture starting
Interface: Wi-Fi
```

### Running

```text
Packet capture started successfully
```

### Stop

```text
Packet capture stopping
```

### Complete

```text
Packet capture stopped
Packets captured: 125430
```

### Error

```text
Packet capture failed
```

Do not log packet payloads or unnecessary sensitive network information.

---

## M4.16 — Application Shutdown

The application should safely stop an active capture when FastAPI shuts down.

Conceptual flow:

```text
Application Shutdown
        ↓
Check Capture State
        ↓
Running?
   +----+----+
   |         |
  Yes        No
   |         |
   v         v
Stop       Continue
Capture
   |
   v
Release Resources
   |
   v
Shutdown
```

---

## M4.17 — Capture Tests

### Dependency

* [x] Scapy imports successfully. (`test_capture_*` suite runs against real Scapy types)
* [x] Correct Scapy version recorded. (2.7.0, pinned `scapy>=2.6.0`)

### Start

* [x] Capture starts with valid interface. (`test_start_uses_selected_interface`)
* [x] State changes to `running`. (`test_status_is_running_after_start`)
* [x] Packet count begins increasing. (`test_packet_count_tracks_sniffer`)

### Stop

* [x] Active capture stops. (`test_stop_returns_to_stopped`)
* [x] State changes to `stopped`. (`test_stop_returns_to_stopped`)
* [x] Final packet count is available. (`test_stop_preserves_final_packet_count`)

### Duplicate Capture

* [x] Second start request is rejected. (`test_second_start_is_rejected`)
* [x] Existing capture remains active. (`test_second_start_is_rejected`)

### Invalid Interface

* [x] Invalid interface is rejected. (`CaptureInterfaceError` when nothing selected / not found)
* [x] Capture does not start. (`test_start_without_selection_is_rejected`)

### Unavailable Interface

* [x] Unavailable interface is rejected. (`test_start_with_unavailable_interface_is_rejected`)
* [x] Controlled error returned. (`CAPTURE_NO_INTERFACE`, HTTP 400)

### Failure

* [x] Permission error is handled. (Scapy start exception → `CaptureStartError`)
* [x] Capture runtime error is handled. (`test_start_failure_is_translated`)
* [x] Application remains operational. (`test_start_failure_allows_retry`)
* [x] Unexpected worker termination is handled. (`test_worker_death_is_detected`)

### Shutdown

* [x] Active capture stops during application shutdown. (`main._stop_active_capture` in lifespan)
* [x] Capture resources are released. (`ScapyCaptureSniffer.stop` closes the sniffer)

---

# M4.18 — API Tests

Test:

```text
GET  /api/v1/capture/status
POST /api/v1/capture/start
POST /api/v1/capture/stop
```

Test scenarios:

* [x] Start with valid selected interface. (`test_start_with_valid_interface`)
* [x] Start when already running. → HTTP 409 (`test_start_when_already_running_is_conflict`)
* [x] Start without a valid interface. → HTTP 400 (`test_start_without_interface_is_rejected`)
* [x] Stop when running. (`test_stop_when_running`)
* [x] Stop when already stopped. → HTTP 409 (`test_stop_when_already_stopped_is_conflict`)
* [x] Invalid HTTP method. → HTTP 405 (`test_invalid_method_on_status`)
* [x] Invalid endpoint. → HTTP 404 (`test_unknown_capture_route_is_404`)
* [x] Correct HTTP status codes.
* [x] Correct response format.

---

# M4.19 — Manual Verification

After automated tests, perform a controlled local test.

```text
Select Interface
       ↓
Start Capture
       ↓
Generate Normal Local Traffic
       ↓
Packet Counter Increases
       ↓
Stop Capture
       ↓
Capture Stops
```

The test should only be performed on an authorized interface/network.

---

# M4.20 — Performance Baseline

At this stage, measure basic capture behavior without implementing the full processing pipeline.

Record:

* Capture startup time.
* Stop time.
* Packet count.
* Approximate packets captured over a fixed period.
* CPU usage.
* Memory usage.

Do not claim production throughput yet.

These measurements establish a baseline for later optimization.

---

# M4 Completion Criteria

M4 is complete when:

* [x] Scapy is installed and recorded in `requirements.txt`.
* [x] Capture Manager exists. (`app/services/capture_manager.py`)
* [x] Capture state is implemented. (`app/services/capture_state.py`)
* [x] Selected M3 interface is used. (manager reads the shared `InterfaceManager`)
* [x] Packet capture starts successfully.
* [x] Packet counter works.
* [x] Packet capture stops successfully.
* [x] Duplicate capture sessions are prevented. (HTTP 409)
* [x] Invalid interfaces are rejected. (HTTP 400)
* [x] Capture errors are handled.
* [x] Application shutdown handles active capture.
* [x] Capture logging works.
* [x] Capture API works. (`GET /status`, `POST /start`, `POST /stop`)
* [x] Automated tests pass. (82 passed, pyright 0 errors)
* [x] Controlled manual capture test passes. (1112 packets / 3s on `Wi-Fi`; live API verified)

---

# Current Immediate Task

**M4.1 — Verify Scapy and prepare the packet-capture dependency.**

First check whether Scapy is already installed:

```powershell
python -c "import scapy; print(scapy.__version__)"
```

Then:

```powershell
pip show scapy
```

Do not implement packet parsing yet.

---

# Development Rule

M4 is responsible only for:

```text
Interface
   ↓
Scapy
   ↓
Packet Capture
   ↓
Capture State
   ↓
Packet Counter
```

Do not add:

* Packet parsing.
* Database packet storage.
* Feature extraction.
* Statistics engine.
* Detection rules.
* Behavioral baselines.
* ML.
* AI.
* WebSocket packet streaming.
* Frontend integration.

These will be implemented in later milestones.

---
