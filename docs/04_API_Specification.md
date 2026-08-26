# NetWatch AI — API Specification

**Project:** NetWatch AI  
**API Version:** v1  
**Status:** In Development  
**Backend Framework:** FastAPI

---

# 1. Overview

The NetWatch AI API provides communication between the React frontend and the backend services.

The API exposes functionality for:

- Dashboard data
- Network capture control
- Packet information
- Device inventory
- Security alerts
- Analytics
- Detection rules
- Behavioral baselines
- Reports
- AI insights
- Notifications
- Application settings
- System health

The API is divided into:


REST API
   +
WebSocket API

REST is primarily used for:

* Historical data
* CRUD operations
* Configuration
* Reports
* Investigation requests

WebSockets are primarily used for:

* Live packets
* Real-time dashboard metrics
* Security alerts
* System status

---

# 2. Technology

## Backend

FastAPI

## Serialization

JSON

## Database

SQLite initially

## Real-Time Communication

WebSockets

---

# 3. Base URL

Development:


http://localhost:8000/api/v1


Example:


http://localhost:8000/api/v1/dashboard


---

# 4. API Documentation

FastAPI automatically provides interactive API documentation.

Swagger UI:

http://localhost:8000/docs


ReDoc:

http://localhost:8000/redoc


These interfaces will be used during development and API testing.

---

# 5. Response Format

Successful response:

```json
{
  "success": true,
  "message": "Request successful",
  "data": {}
}
```

Error response:

```json
{
  "success": false,
  "message": "Request failed",
  "errors": []
}
```

---

# 6. Pagination Format

Endpoints returning large collections should support pagination.

Example:

```text
GET /api/v1/packets?page=1&limit=100
```

Response:

```json
{
  "success": true,
  "data": {
    "items": [],
    "page": 1,
    "limit": 100,
    "total": 10000,
    "total_pages": 100
  }
}
```

Pagination prevents large packet and alert datasets from being returned in a single response.

---

# 7. Filtering

Collection endpoints should support appropriate filters.

Example:

```text
GET /api/v1/alerts?severity=high&status=new
```

Possible filters include:

* Severity
* Status
* Protocol
* Source IP
* Destination IP
* Device ID
* Date/time range

---

# 8. Authentication

## Initial Version

The first local version will operate without authentication.

This keeps the project simple and suitable for a single-user local environment.

## Future Version

Authentication can be added using:

* JWT
* Secure password hashing
* Role-based access control

Future roles:

```text
admin
analyst
viewer
```

---

# 9. Dashboard API

## GET /dashboard

Returns the main dashboard metrics.

### Response

```json
{
  "success": true,
  "data": {
    "packets_per_second": 952,
    "bandwidth_mbps": 32.6,
    "active_devices": 12,
    "active_connections": 41,
    "active_alerts": 3,
    "threat_score": 18
  }
}
```

---

## GET /dashboard/traffic

Returns recent traffic metrics for the dashboard chart.

Query parameters:

```text
range
interval
```

Example:

```text
GET /api/v1/dashboard/traffic?range=15m&interval=1s
```

Response:

```json
{
  "success": true,
  "data": [
    {
      "timestamp": "2026-08-24T20:00:00Z",
      "packets_per_second": 842,
      "bytes_per_second": 3500000
    }
  ]
}
```

---

## GET /dashboard/protocols

Returns current protocol distribution.

Response:

```json
{
  "success": true,
  "data": [
    {
      "protocol": "TCP",
      "packets": 4500,
      "bytes": 5500000
    },
    {
      "protocol": "UDP",
      "packets": 2100,
      "bytes": 1300000
    }
  ]
}
```

---

## GET /dashboard/top-talkers

Returns devices or IP addresses consuming the most traffic.

Query parameters:

```text
limit
```

Example:

```text
GET /api/v1/dashboard/top-talkers?limit=10
```

---

## GET /dashboard/ai-summary

Returns the current high-level AI security summary.

Response:

```json
{
  "success": true,
  "data": {
    "summary": "No critical threats detected. One device is showing elevated DNS activity.",
    "risk_score": 28,
    "confidence": 89,
    "recommendation": "Monitor the affected device."
  }
}
```

---

# 10. Capture API

## GET /capture/interfaces

Returns available network interfaces.

Response:

```json
{
  "success": true,
  "data": [
    {
      "name": "Wi-Fi",
      "description": "Wireless Network Adapter"
    },
    {
      "name": "Ethernet",
      "description": "Ethernet Adapter"
    }
  ]
}
```

---

## GET /capture/status

Returns the current capture status.

Response:

```json
{
  "success": true,
  "data": {
    "running": true,
    "interface": "Wi-Fi",
    "captured_packets": 891231,
    "started_at": "2026-08-24T19:30:00Z"
  }
}
```

---

## POST /capture/start

Starts packet capture.

Request:

```json
{
  "interface": "Wi-Fi"
}
```

Response:

```json
{
  "success": true,
  "message": "Packet capture started",
  "data": {
    "interface": "Wi-Fi",
    "status": "running"
  }
}
```

---

## POST /capture/stop

Stops packet capture.

Response:

```json
{
  "success": true,
  "message": "Packet capture stopped",
  "data": {
    "status": "stopped"
  }
}
```

---

# 11. Packet API

## GET /packets

Returns captured packet metadata.

Query parameters:

```text
page
limit
source_ip
destination_ip
protocol
source_port
destination_port
device_id
start_time
end_time
```

Example:

```text
GET /api/v1/packets?page=1&limit=100&protocol=TCP
```

Response:

```json
{
  "success": true,
  "data": {
    "items": [
      {
        "id": 1001,
        "timestamp": "2026-08-24T20:12:31Z",
        "source_ip": "192.168.1.20",
        "destination_ip": "8.8.8.8",
        "source_port": 52213,
        "destination_port": 443,
        "protocol": "TCP",
        "packet_length": 1460,
        "ttl": 64,
        "tcp_flags": "ACK"
      }
    ],
    "page": 1,
    "limit": 100,
    "total": 10000
  }
}
```

---

## GET /packets/{packet_id}

Returns packet details.

Response may include:

```text
Packet Metadata
Ethernet Information
IP Information
Transport Header
Related Device
Related Alerts
Risk Information
```

Example:

```json
{
  "success": true,
  "data": {
    "id": 1001,
    "timestamp": "2026-08-24T20:12:31Z",
    "source_ip": "192.168.1.20",
    "destination_ip": "8.8.8.8",
    "source_port": 52213,
    "destination_port": 443,
    "protocol": "TCP",
    "packet_length": 1460,
    "ttl": 64,
    "tcp_flags": "ACK"
  }
}
```

---

# 12. Device API

## GET /devices

Returns observed network devices.

Query parameters:

```text
page
limit
status
device_type
search
```

---

## GET /devices/{device_id}

Returns detailed information for one device.

Response:

```json
{
  "success": true,
  "data": {
    "id": 12,
    "ip_address": "192.168.1.20",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "hostname": "Aman-PC",
    "vendor": "Example Vendor",
    "operating_system": "Windows",
    "device_type": "workstation",
    "status": "online",
    "risk_score": 18,
    "trust_score": 70,
    "total_packets": 123456,
    "total_bytes": 987654321
  }
}
```

---

## GET /devices/{device_id}/traffic

Returns historical traffic for a device.

---

## GET /devices/{device_id}/connections

Returns active and historical connections associated with the device.

---

## GET /devices/{device_id}/alerts

Returns alerts related to the device.

---

## GET /devices/{device_id}/baseline

Returns the behavioral baseline associated with the device.

---

# 13. Alert API

## GET /alerts

Returns security alerts.

Query parameters:

```text
page
limit
severity
status
device_id
source_ip
start_time
end_time
```

Example:

```text
GET /api/v1/alerts?severity=high&status=new
```

---

## GET /alerts/{alert_id}

Returns complete alert information.

The response should include:

* Alert metadata
* Detection rule
* Device
* Evidence
* Related events
* AI insights
* Risk information

---

## POST /alerts/{alert_id}/acknowledge

Changes the alert status to:

```text
acknowledged
```

---

## POST /alerts/{alert_id}/investigate

Changes the alert status to:

```text
investigating
```

---

## POST /alerts/{alert_id}/resolve

Changes the alert status to:

```text
resolved
```

---

## POST /alerts/{alert_id}/false-positive

Marks the alert as:

```text
false_positive
```

The system should retain this feedback for future detection tuning.

---

# 14. Alert Evidence API

## GET /alerts/{alert_id}/evidence

Returns the evidence associated with an alert.

Possible evidence types:

```text
packet
connection
behavioral
rule
ml
device
```

Example:

```json
{
  "success": true,
  "data": [
    {
      "id": 101,
      "evidence_type": "behavioral",
      "evidence_data": {
        "normal_packets_per_second": 80,
        "current_packets_per_second": 2400
      }
    }
  ]
}
```

---

# 15. Analytics API

## GET /analytics/traffic

Returns traffic history.

Query parameters:

```text
start_time
end_time
interval
```

---

## GET /analytics/protocols

Returns protocol usage over a selected period.

---

## GET /analytics/top-talkers

Returns highest traffic-generating devices or IPs.

---

## GET /analytics/top-ports

Returns most frequently observed destination ports.

---

## GET /analytics/threats

Returns threat trends over time.

---

## GET /analytics/packets

Returns packet statistics.

---

## GET /analytics/connections

Returns connection statistics.

---

# 16. Detection Rules API

## GET /detection-rules

Returns configured detection rules.

Response:

```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "rule_key": "PORT_SCAN_001",
      "rule_name": "Port Scan Detection",
      "detection_type": "rule",
      "severity": "high",
      "enabled": true,
      "threshold_config": {
        "unique_ports": 40,
        "syn_ratio": 0.6
      },
      "time_window_seconds": 30
    }
  ]
}
```

---

## GET /detection-rules/{rule_id}

Returns one detection rule.

---

## PUT /detection-rules/{rule_id}

Updates a detection rule.

Example request:

```json
{
  "enabled": true,
  "threshold_config": {
    "unique_ports": 50,
    "syn_ratio": 0.7
  },
  "time_window_seconds": 30
}
```

---

## POST /detection-rules/{rule_id}/enable

Enables a detection rule.

---

## POST /detection-rules/{rule_id}/disable

Disables a detection rule.

---

# 17. Behavioral Baseline API

## GET /baselines/{device_id}

Returns the baseline for a device.

---

## POST /baselines/{device_id}/reset

Resets a device's baseline.

This should be used when a device's normal behavior changes significantly.

---

## POST /baselines/{device_id}/pause

Temporarily prevents baseline updates.

---

## POST /baselines/{device_id}/resume

Resumes baseline learning.

---

# 18. ML API

## GET /ml/status

Returns ML engine status.

Example:

```json
{
  "success": true,
  "data": {
    "enabled": true,
    "model": "IsolationForest",
    "status": "ready"
  }
}
```

---

## GET /ml/anomalies

Returns recent anomaly events.

Query parameters:

```text
page
limit
device_id
start_time
end_time
```

---

# 19. AI API

The AI API is responsible for analyst assistance rather than primary packet detection.

## GET /ai/insights

Returns recent AI insights.

---

## GET /ai/alerts/{alert_id}

Generates or retrieves AI analysis for an alert.

Response:

```json
{
  "success": true,
  "data": {
    "summary": "The source host exhibited behavior consistent with network reconnaissance.",
    "explanation": "The host contacted 57 unique ports within 30 seconds and generated a high percentage of failed connections.",
    "recommendation": "Determine whether the source host is authorized to perform network discovery.",
    "confidence": 94
  }
}
```

---

## GET /ai/devices/{device_id}

Returns AI-assisted analysis of device behavior.

---

## POST /ai/analyze

Requests AI analysis of a structured security event.

Request:

```json
{
  "event_type": "port_scan",
  "alert_id": 105
}
```

The AI service must use evidence retrieved from the system rather than relying on unsupported assumptions.

---

# 20. Reports API

## GET /reports

Returns report history.

Query parameters:

```text
page
limit
report_type
format
```

---

## GET /reports/{report_id}

Returns report metadata.

---

## POST /reports/generate

Generates a report.

Request:

```json
{
  "report_type": "weekly",
  "format": "pdf",
  "start_time": "2026-08-17T00:00:00Z",
  "end_time": "2026-08-24T23:59:59Z"
}
```

Response:

```json
{
  "success": true,
  "data": {
    "report_id": 25,
    "status": "processing"
  }
}
```

---

## GET /reports/{report_id}/download

Downloads the generated report.

---

## DELETE /reports/{report_id}

Deletes a generated report.

---

# 21. Settings API

## GET /settings

Returns application settings.

---

## GET /settings/{setting_key}

Returns one setting.

---

## PUT /settings

Updates application settings.

Example:

```json
{
  "capture_interface": "Wi-Fi",
  "ai_enabled": true,
  "packet_retention_days": 30,
  "default_theme": "dark"
}
```

---

## POST /settings/reset

Restores default settings.

---

# 22. System API

## GET /system/status

Returns health of system components.

Example:

```json
{
  "success": true,
  "data": {
    "capture_engine": "healthy",
    "database": "healthy",
    "api": "healthy",
    "websocket": "healthy",
    "detection_engine": "healthy",
    "ml_engine": "healthy",
    "ai_engine": "healthy"
  }
}
```

---

## GET /system/info

Returns system information.

Example:

```json
{
  "success": true,
  "data": {
    "version": "1.0.0",
    "platform": "Windows",
    "uptime_seconds": 3821,
    "database": "SQLite"
  }
}
```

---

# 23. Notifications API

## GET /notifications

Returns notifications for the current user.

Query parameters:

```text
page
limit
unread_only
```

---

## POST /notifications/{notification_id}/read

Marks a notification as read.

---

## POST /notifications/read-all

Marks all notifications as read.

---

## DELETE /notifications/{notification_id}

Deletes a notification.

---

# 24. WebSocket API

REST APIs are not sufficient for live packet monitoring.

NetWatch AI therefore uses WebSockets for real-time updates.

---

# 25. WebSocket: Dashboard

Endpoint:

```text
ws://localhost:8000/ws/dashboard
```

Events may include:

```text
dashboard_metrics
traffic_update
device_update
system_status
```

Example:

```json
{
  "event": "dashboard_metrics",
  "data": {
    "packets_per_second": 952,
    "bandwidth_mbps": 32.6,
    "active_devices": 12,
    "active_alerts": 3
  }
}
```

---

# 26. WebSocket: Packets

Endpoint:

```text
ws://localhost:8000/ws/packets
```

Used by the Live Traffic page.

Example:

```json
{
  "event": "packet",
  "data": {
    "timestamp": "2026-08-24T20:15:10Z",
    "source_ip": "192.168.1.20",
    "destination_ip": "8.8.8.8",
    "protocol": "DNS",
    "packet_length": 84
  }
}
```

---

# 27. WebSocket: Alerts

Endpoint:

```text
ws://localhost:8000/ws/alerts
```

Example event:

```json
{
  "event": "new_alert",
  "data": {
    "id": 105,
    "title": "Potential Port Scan",
    "severity": "high",
    "risk_score": 86,
    "confidence": 94
  }
}
```

---

# 28. WebSocket: System

Endpoint:

```text
ws://localhost:8000/ws/system
```

Used for live system-health information.

Example:

```json
{
  "event": "system_status",
  "data": {
    "capture_engine": "healthy",
    "database": "healthy",
    "detection_engine": "healthy"
  }
}
```

---

# 29. HTTP Status Codes

The API should use standard HTTP status codes.

| Code | Meaning                            |
| ---: | ---------------------------------- |
|  200 | Request successful                 |
|  201 | Resource created                   |
|  204 | Successful request with no content |
|  400 | Bad request                        |
|  401 | Authentication required            |
|  403 | Forbidden                          |
|  404 | Resource not found                 |
|  409 | Conflict                           |
|  422 | Validation error                   |
|  429 | Too many requests                  |
|  500 | Internal server error              |
|  503 | Service unavailable                |

The initial unauthenticated local version will primarily use 200, 201, 400, 404, 422, 500, and 503.

---

# 30. Error Handling

All API errors should use a consistent format.

Example:

```json
{
  "success": false,
  "message": "Device not found",
  "errors": [
    {
      "field": "device_id",
      "code": "NOT_FOUND"
    }
  ]
}
```

Internal exception details should not be exposed directly to the frontend.

---

# 31. Input Validation

FastAPI request schemas should validate incoming data.

Examples:

## Port

```text
0–65535
```

## Risk Score

```text
0–100
```

## Confidence

```text
0–100
```

## Page

```text
>= 1
```

## Limit

A configurable maximum should prevent excessively large API responses.

---

# 32. Rate Limiting

The initial local version does not require aggressive rate limiting.

Future versions should introduce API rate limiting, especially for:

* Authentication endpoints
* AI analysis requests
* Report generation
* Administrative operations

A possible future default is:

```text
100 requests/minute/client
```

The final value should be validated during deployment testing.

---

# 33. API Versioning

The API uses explicit versioning:

```text
/api/v1/
```

Future incompatible changes can use:

```text
/api/v2/
```

This prevents breaking existing clients when the API evolves.

---

# 34. API-to-Database Mapping

| API Module      | Main Database Entities                                        |
| --------------- | ------------------------------------------------------------- |
| Dashboard       | traffic_statistics, protocol_statistics, alerts, devices      |
| Capture         | settings, system_status, packets                              |
| Packets         | packets                                                       |
| Devices         | devices, behavioral_baselines                                 |
| Alerts          | alerts, alert_evidence                                        |
| Detection Rules | detection_rules                                               |
| Analytics       | traffic_statistics, protocol_statistics, packets, connections |
| AI              | ai_insights, alerts, behavioral_baselines                     |
| Reports         | reports                                                       |
| Settings        | settings                                                      |
| System          | system_status                                                 |
| Notifications   | notifications                                                 |

---

# 35. API-to-Frontend Mapping

| Frontend Page       | Primary API                  |
| ------------------- | ---------------------------- |
| Dashboard           | /dashboard, /dashboard/*     |
| Live Traffic        | /packets + /ws/packets       |
| Packet Details      | /packets/{id}                |
| Devices             | /devices                     |
| Device Details      | /devices/{id}/*              |
| Alerts              | /alerts                      |
| Alert Investigation | /alerts/{id} + evidence + AI |
| Analytics           | /analytics/*                 |
| Reports             | /reports/*                   |
| Settings            | /settings + /detection-rules |

---

# 36. API Architecture

```text
                         React Frontend
                              |
                  +-----------+-----------+
                  |                       |
                  v                       v
              REST API               WebSockets
                  |                       |
                  +-----------+-----------+
                              |
                              v
                        FastAPI Backend
                              |
          +-------------------+-------------------+
          |                   |                   |
          v                   v                   v
      Services           Detection            AI Service
          |                   |                   |
          +-------------------+-------------------+
                              |
                              v
                       Repository Layer
                              |
                              v
                           SQLite
```

---

# 37. API Security Architecture

Future authentication:

```text
Client
  |
  v
Authentication
  |
  v
JWT Token
  |
  v
FastAPI
  |
  v
Authorization
  |
  v
Service
```

The API should never expose direct database access to the frontend.

---

# 38. API Performance Considerations

The API should:

* Paginate large datasets.
* Avoid returning unnecessary fields.
* Use database indexes.
* Cache frequently requested dashboard metrics where useful.
* Use WebSockets for high-frequency live data.
* Avoid polling every packet through REST.
* Use asynchronous/background processing for long-running reports.

---

# 39. Long-Running Operations

Some operations may take longer than a normal HTTP request.

Examples:

* Report generation
* Large historical analysis
* Model training
* Large PCAP analysis
* AI analysis

The initial response should acknowledge the task:

```json
{
  "success": true,
  "data": {
    "status": "processing",
    "job_id": "job-123"
  }
}
```

A future job-status endpoint can track progress:

```text
GET /api/v1/jobs/{job_id}
```

---

# 40. API Testing Strategy

Each endpoint should eventually have:

* Unit tests
* Integration tests
* Input-validation tests
* Error-handling tests

Examples:

```text
GET /devices/1
    → 200

GET /devices/999999
    → 404

POST /capture/start
    → 200

POST /capture/start with invalid interface
    → 422 or 400
```

---

# 41. Future API Extensions

Possible future endpoints:

```text
/api/v1/threat-intelligence
/api/v1/mitre
/api/v1/integrations
/api/v1/zeek
/api/v1/suricata
/api/v1/webhooks
/api/v1/sensors
/api/v1/users
/api/v1/auth
```

These should be introduced only when the corresponding functionality is implemented.

---

# 42. API Design Principles

NetWatch AI follows these principles:

1. Keep APIs resource-oriented.
2. Use REST for historical and configuration operations.
3. Use WebSockets for high-frequency real-time updates.
4. Use pagination for large datasets.
5. Validate all incoming data.
6. Return consistent response structures.
7. Keep database access behind the service/repository layers.
8. Separate detection logic from API route logic.
9. Avoid exposing internal implementation details.
10. Version the API.
11. Make long-running operations asynchronous where appropriate.
12. Keep authentication optional for the first local release and extensible for future versions.

---

# 43. Endpoint Summary

| Module          | Main Endpoints          |
| --------------- | ----------------------- |
| Dashboard       | `/dashboard/*`          |
| Capture         | `/capture/*`            |
| Packets         | `/packets/*`            |
| Devices         | `/devices/*`            |
| Alerts          | `/alerts/*`             |
| Evidence        | `/alerts/{id}/evidence` |
| Detection Rules | `/detection-rules/*`    |
| Baselines       | `/baselines/*`          |
| ML              | `/ml/*`                 |
| AI              | `/ai/*`                 |
| Analytics       | `/analytics/*`          |
| Reports         | `/reports/*`            |
| Settings        | `/settings/*`           |
| System          | `/system/*`             |
| Notifications   | `/notifications/*`      |

---

# 44. Conclusion

The NetWatch AI API provides a structured interface between the frontend and the backend security platform.

The architecture intentionally separates:

```text
REST API
    ↓
Business Services
    ↓
Detection / Analytics / AI
    ↓
Repository Layer
    ↓
Database
```

while real-time information follows:

```text
Network Processing
       ↓
Event Generation
       ↓
WebSocket Service
       ↓
React Dashboard
```

This separation allows the application to provide real-time network visibility while keeping historical queries, configuration, alert investigation, reporting, and AI analysis organized through a consistent API.

The API design is intended to remain simple enough for the initial local deployment while providing a clean foundation for future authentication, distributed sensors, external integrations, and production deployment.


