# NetWatch AI — Database Design

**Project:** NetWatch AI  
**Database Version:** 1.0  
**Status:** In Development  
**Primary Database:** SQLite  
**Future Production Option:** PostgreSQL

---

# 1. Overview

The NetWatch AI database stores the persistent information required by the network monitoring, security detection, analytics, alert management, reporting, and AI analysis components.

The database is designed around the system architecture defined in:


@ docs/02_System_Architecture.md


The database should support:

* Network device inventory
* Captured packet metadata
* Network connections
* Traffic statistics
* Protocol statistics
* Security alerts
* Alert evidence
* Detection rule configuration
* Behavioral baselines
* AI analysis results
* Reports
* Application settings
* System health information
* Notifications

The database should provide a balance between simplicity for local development and a clear migration path to a production-grade relational database.

---

# 2. Database Objectives

The database should:

1. Store persistent network and security information.
2. Support real-time dashboard queries.
3. Support historical analytics.
4. Preserve evidence associated with security alerts.
5. Support configurable detection rules.
6. Store behavioral baseline information.
7. Store AI-generated analysis associated with security events.
8. Avoid unnecessary storage of high-volume data.
9. Support efficient searches through indexing.
10. Maintain referential integrity between related entities.

---

# 3. Database Technology

## Initial Implementation

**SQLite**

SQLite is selected for the initial implementation because:

* It is free and open source.
* It requires no separate database server.
* It is simple to deploy locally.
* It is suitable for the initial single-machine project.
* It reduces infrastructure requirements during development.

---

## Future Production Option

The database can later be migrated to:

**PostgreSQL**

A larger deployment may also consider a time-series database extension or platform for high-volume network telemetry.

The application should therefore avoid tightly coupling business logic directly to SQLite-specific behavior.

---

# 4. Database Architecture

```text
                         +----------------+
                         |     Users      |
                         +-------+--------+
                                 |
                                 v
                         +----------------+
                         |    Reports     |
                         +----------------+

+-----------+       +-----------+       +-------------+
|  Devices  |------>|  Packets  |------>| Connections |
+-----+-----+       +-----+-----+       +-------------+
      |                   |
      |                   |
      v                   v
+-----------+       +-------------+
| Baselines |       |   Alerts    |
+-----------+       +------+------+
                           |
                           v
                   +----------------+
                   | Alert Evidence |
                   +----------------+
                           |
              +------------+------------+
              |                         |
              v                         v
      +---------------+         +---------------+
      | AI Insights   |         | Detection     |
      |               |         | Rules         |
      +---------------+         +---------------+

+----------------------+       +----------------------+
| Traffic Statistics   |       | Protocol Statistics  |
+----------------------+       +----------------------+

+----------------------+       +----------------------+
| Settings             |       | System Status        |
+----------------------+       +----------------------+

+----------------------+
| Notifications        |
+----------------------+
```

---

# 5. Core Entities

The initial schema contains the following major entities:

```text
users
devices
packets
connections
alerts
alert_evidence
detection_rules
behavioral_baselines
traffic_statistics
protocol_statistics
ai_insights
reports
settings
system_status
notifications
```

---

# 6. Entity Relationships

The primary relationships are:

```text
User
 |
 +---- Reports
 |
 +---- Notifications

Device
 |
 +---- Packets
 |
 +---- Connections
 |
 +---- Alerts
 |
 +---- Behavioral Baseline

Detection Rule
 |
 +---- Alerts

Alert
 |
 +---- Alert Evidence
 |
 +---- AI Insights

Packets
 |
 +---- Connections
 |
 +---- Alerts

Traffic Statistics
Protocol Statistics

Settings
System Status
```

---

# 7. Table: users

## Purpose

Stores application users.

The initial local version may operate without authentication, but the table provides a foundation for future authentication and role-based access control.

## Schema

| Column        | Type     | Constraints      | Description           |
| ------------- | -------- | ---------------- | --------------------- |
| id            | INTEGER  | PK               | Unique user ID        |
| username      | TEXT     | UNIQUE, NOT NULL | Username              |
| email         | TEXT     | UNIQUE           | User email            |
| password_hash | TEXT     | NULL             | Secure password hash  |
| role          | TEXT     | NOT NULL         | User role             |
| created_at    | DATETIME | NOT NULL         | Account creation time |
| last_login    | DATETIME | NULL             | Last login time       |

Possible roles:

```text
admin
analyst
viewer
```

---

# 8. Table: devices

## Purpose

Stores devices observed by the monitoring system.

## Schema

| Column           | Type     | Constraints | Description                  |
| ---------------- | -------- | ----------- | ---------------------------- |
| id               | INTEGER  | PK          | Device ID                    |
| ip_address       | TEXT     | NOT NULL    | IPv4/IPv6 address            |
| mac_address      | TEXT     | NULL        | MAC address                  |
| hostname         | TEXT     | NULL        | Hostname                     |
| vendor           | TEXT     | NULL        | Hardware/vendor              |
| operating_system | TEXT     | NULL        | OS information               |
| device_type      | TEXT     | NULL        | Laptop, router, server, etc. |
| first_seen       | DATETIME | NOT NULL    | First observation            |
| last_seen        | DATETIME | NOT NULL    | Most recent observation      |
| status           | TEXT     | NOT NULL    | Online/offline/unknown       |
| risk_score       | INTEGER  | DEFAULT 0   | Current device risk          |
| trust_score      | INTEGER  | DEFAULT 50  | Contextual trust score       |
| total_packets    | INTEGER  | DEFAULT 0   | Packet count                 |
| total_bytes      | INTEGER  | DEFAULT 0   | Total traffic volume         |

## Device States

```text
online
offline
unknown
```

## Device Lifecycle

```text
First Observed
      |
      v
Create Device
      |
      v
Update on New Traffic
      |
      v
Update Last Seen
      |
      v
Calculate Risk / Behavioral Profile
```

---

# 9. Table: packets

## Purpose

Stores normalized packet metadata required for monitoring, investigations, and security evidence.

Raw payloads should not be stored by default.

## Schema

| Column           | Type     | Constraints | Description          |
| ---------------- | -------- | ----------- | -------------------- |
| id               | INTEGER  | PK          | Packet ID            |
| timestamp        | DATETIME | NOT NULL    | Packet capture time  |
| source_ip        | TEXT     | NOT NULL    | Source IP            |
| destination_ip   | TEXT     | NOT NULL    | Destination IP       |
| source_port      | INTEGER  | NULL        | Source port          |
| destination_port | INTEGER  | NULL        | Destination port     |
| protocol         | TEXT     | NOT NULL    | TCP, UDP, ICMP, etc. |
| packet_length    | INTEGER  | NOT NULL    | Packet size          |
| ttl              | INTEGER  | NULL        | IP TTL               |
| tcp_flags        | TEXT     | NULL        | TCP flags            |
| payload_length   | INTEGER  | NULL        | Payload size         |
| device_id        | INTEGER  | FK          | Associated device    |
| processed        | INTEGER  | DEFAULT 0   | Processing status    |
| created_at       | DATETIME | NOT NULL    | Record creation time |

Foreign key:

```text
packets.device_id
        ↓
devices.id
```

---

# 10. Table: connections

## Purpose

Stores aggregated network connection/session information instead of requiring the application to reconstruct sessions from raw packets for every query.

## Schema

| Column                | Type     | Constraints | Description        |
| --------------------- | -------- | ----------- | ------------------ |
| id                    | INTEGER  | PK          | Connection ID      |
| source_device_id      | INTEGER  | FK          | Source device      |
| destination_device_id | INTEGER  | FK, NULL    | Destination device |
| source_ip             | TEXT     | NOT NULL    | Source IP          |
| destination_ip        | TEXT     | NOT NULL    | Destination IP     |
| source_port           | INTEGER  | NULL        | Source port        |
| destination_port      | INTEGER  | NULL        | Destination port   |
| protocol              | TEXT     | NOT NULL    | Protocol           |
| packets_sent          | INTEGER  | DEFAULT 0   | Packets sent       |
| packets_received      | INTEGER  | DEFAULT 0   | Packets received   |
| bytes_sent            | INTEGER  | DEFAULT 0   | Bytes sent         |
| bytes_received        | INTEGER  | DEFAULT 0   | Bytes received     |
| start_time            | DATETIME | NOT NULL    | Connection start   |
| end_time              | DATETIME | NULL        | Connection end     |
| status                | TEXT     | NOT NULL    | Connection status  |

Possible statuses:

```text
active
completed
failed
timeout
```

---

# 11. Table: alerts

## Purpose

Stores security findings generated by the detection and correlation engine.

## Schema

| Column          | Type     | Constraints | Description                   |
| --------------- | -------- | ----------- | ----------------------------- |
| id              | INTEGER  | PK          | Alert ID                      |
| rule_id         | INTEGER  | FK, NULL    | Triggering detection rule     |
| device_id       | INTEGER  | FK, NULL    | Main affected device          |
| source_ip       | TEXT     | NULL        | Source IP                     |
| destination_ip  | TEXT     | NULL        | Destination IP                |
| title           | TEXT     | NOT NULL    | Alert title                   |
| description     | TEXT     | NULL        | Alert description             |
| severity        | TEXT     | NOT NULL    | Severity                      |
| risk_score      | INTEGER  | NOT NULL    | Risk value                    |
| confidence      | INTEGER  | NOT NULL    | Detection confidence          |
| status          | TEXT     | NOT NULL    | Alert state                   |
| correlation_key | TEXT     | NULL        | Deduplication/correlation key |
| created_at      | DATETIME | NOT NULL    | Alert creation                |
| updated_at      | DATETIME | NOT NULL    | Last update                   |
| resolved_at     | DATETIME | NULL        | Resolution time               |

Possible severity:

```text
critical
high
medium
low
```

Possible statuses:

```text
new
acknowledged
investigating
resolved
false_positive
```

---

# 12. Table: alert_evidence

## Purpose

Stores evidence associated with an alert.

This allows an alert to reference multiple pieces of supporting information.

## Schema

| Column        | Type     | Constraints  | Description         |
| ------------- | -------- | ------------ | ------------------- |
| id            | INTEGER  | PK           | Evidence ID         |
| alert_id      | INTEGER  | FK, NOT NULL | Related alert       |
| packet_id     | INTEGER  | FK, NULL     | Related packet      |
| evidence_type | TEXT     | NOT NULL     | Evidence category   |
| evidence_data | TEXT     | NOT NULL     | Structured evidence |
| created_at    | DATETIME | NOT NULL     | Evidence time       |

Examples of evidence types:

```text
packet
connection
behavioral
rule
ml
device
```

---

# 13. Table: detection_rules

## Purpose

Stores configurable detection rules.

Detection logic should not depend entirely on hard-coded thresholds.

## Schema

| Column              | Type     | Constraints | Description            |
| ------------------- | -------- | ----------- | ---------------------- |
| id                  | INTEGER  | PK          | Rule ID                |
| rule_key            | TEXT     | UNIQUE      | Stable rule identifier |
| rule_name           | TEXT     | NOT NULL    | Display name           |
| description         | TEXT     | NULL        | Rule description       |
| detection_type      | TEXT     | NOT NULL    | Rule category          |
| severity            | TEXT     | NOT NULL    | Default severity       |
| enabled             | INTEGER  | DEFAULT 1   | Rule enabled/disabled  |
| threshold_config    | TEXT     | NULL        | JSON configuration     |
| time_window_seconds | INTEGER  | NULL        | Detection window       |
| version             | INTEGER  | DEFAULT 1   | Rule version           |
| created_at          | DATETIME | NOT NULL    | Creation time          |
| updated_at          | DATETIME | NOT NULL    | Last update            |

Example:

```json
{
  "unique_ports": 40,
  "syn_ratio": 0.60,
  "failed_connections": 20
}
```

---

# 14. Table: behavioral_baselines

## Purpose

Stores behavioral profiles for devices.

The baseline allows the system to detect deviations from normal activity.

## Schema

| Column                  | Type     | Constraints | Description               |
| ----------------------- | -------- | ----------- | ------------------------- |
| id                      | INTEGER  | PK          | Baseline ID               |
| device_id               | INTEGER  | FK, UNIQUE  | Associated device         |
| status                  | TEXT     | NOT NULL    | Learning/active           |
| observation_count       | INTEGER  | DEFAULT 0   | Number of observations    |
| avg_packets_per_second  | REAL     | NULL        | Average packet rate       |
| avg_bytes_per_second    | REAL     | NULL        | Average bandwidth         |
| avg_unique_destinations | REAL     | NULL        | Average destination count |
| avg_unique_ports        | REAL     | NULL        | Average port count        |
| avg_packet_size         | REAL     | NULL        | Average packet size       |
| normal_tcp_ratio        | REAL     | NULL        | Typical TCP ratio         |
| normal_udp_ratio        | REAL     | NULL        | Typical UDP ratio         |
| normal_icmp_ratio       | REAL     | NULL        | Typical ICMP ratio        |
| created_at              | DATETIME | NOT NULL    | Baseline creation         |
| updated_at              | DATETIME | NOT NULL    | Last update               |

Possible states:

```text
learning
active
disabled
```

---

# 15. Table: traffic_statistics

## Purpose

Stores aggregated network traffic metrics used by the dashboard and historical analytics.

## Schema

| Column             | Type     | Constraints | Description            |
| ------------------ | -------- | ----------- | ---------------------- |
| id                 | INTEGER  | PK          | Statistic ID           |
| timestamp          | DATETIME | NOT NULL    | Measurement time       |
| packets_per_second | REAL     | NOT NULL    | Packet rate            |
| bytes_per_second   | REAL     | NOT NULL    | Traffic rate           |
| active_devices     | INTEGER  | NOT NULL    | Active devices         |
| active_connections | INTEGER  | NOT NULL    | Active connections     |
| active_alerts      | INTEGER  | NOT NULL    | Current alerts         |
| total_packets      | INTEGER  | NOT NULL    | Total observed packets |
| total_bytes        | INTEGER  | NOT NULL    | Total observed bytes   |

---

# 16. Table: protocol_statistics

## Purpose

Stores traffic statistics by protocol.

## Schema

| Column       | Type     | Constraints | Description       |
| ------------ | -------- | ----------- | ----------------- |
| id           | INTEGER  | PK          | Statistic ID      |
| timestamp    | DATETIME | NOT NULL    | Measurement time  |
| protocol     | TEXT     | NOT NULL    | Protocol name     |
| packet_count | INTEGER  | NOT NULL    | Number of packets |
| byte_count   | INTEGER  | NOT NULL    | Traffic volume    |

Example:

```text
TCP
UDP
ICMP
DNS
HTTP
HTTPS
SSH
```

---

# 17. Table: ai_insights

## Purpose

Stores AI-generated analysis associated with network events or security alerts.

## Schema

| Column         | Type     | Constraints | Description          |
| -------------- | -------- | ----------- | -------------------- |
| id             | INTEGER  | PK          | Insight ID           |
| alert_id       | INTEGER  | FK, NULL    | Related alert        |
| device_id      | INTEGER  | FK, NULL    | Related device       |
| insight_type   | TEXT     | NOT NULL    | Type of analysis     |
| summary        | TEXT     | NOT NULL    | AI summary           |
| explanation    | TEXT     | NULL        | Detailed explanation |
| recommendation | TEXT     | NULL        | Recommended action   |
| confidence     | INTEGER  | NULL        | AI confidence        |
| model_name     | TEXT     | NULL        | Model used           |
| created_at     | DATETIME | NOT NULL    | Generation time      |

Possible insight types:

```text
alert_summary
device_analysis
traffic_summary
investigation_guidance
```

---

# 18. Table: reports

## Purpose

Stores metadata for generated reports.

The report file itself may be stored on the local filesystem rather than directly inside the database.

## Schema

| Column       | Type     | Constraints | Description         |
| ------------ | -------- | ----------- | ------------------- |
| id           | INTEGER  | PK          | Report ID           |
| name         | TEXT     | NOT NULL    | Report name         |
| report_type  | TEXT     | NOT NULL    | Daily/weekly/custom |
| format       | TEXT     | NOT NULL    | PDF/CSV             |
| generated_by | INTEGER  | FK, NULL    | User                |
| file_path    | TEXT     | NOT NULL    | File location       |
| generated_at | DATETIME | NOT NULL    | Generation time     |

---

# 19. Table: settings

## Purpose

Stores application configuration.

A key-value design keeps the initial settings system flexible.

## Schema

| Column        | Type     | Constraints      | Description         |
| ------------- | -------- | ---------------- | ------------------- |
| id            | INTEGER  | PK               | Setting ID          |
| setting_key   | TEXT     | UNIQUE, NOT NULL | Configuration key   |
| setting_value | TEXT     | NOT NULL         | Configuration value |
| data_type     | TEXT     | NOT NULL         | Value type          |
| updated_at    | DATETIME | NOT NULL         | Last update         |

Examples:

```text
capture_interface
capture_enabled
packet_retention_days
default_theme
ai_enabled
alert_threshold
```

---

# 20. Table: system_status

## Purpose

Stores the current operational state of system components.

## Schema

| Column         | Type     | Constraints      | Description     |
| -------------- | -------- | ---------------- | --------------- |
| id             | INTEGER  | PK               | Status ID       |
| component_name | TEXT     | UNIQUE, NOT NULL | Component       |
| status         | TEXT     | NOT NULL         | Health state    |
| metric_value   | REAL     | NULL             | Optional metric |
| message        | TEXT     | NULL             | Status message  |
| updated_at     | DATETIME | NOT NULL         | Last update     |

Possible components:

```text
capture_engine
database
api
websocket
detection_engine
ml_engine
ai_engine
```

---

# 21. Table: notifications

## Purpose

Stores user-visible notifications.

## Schema

| Column            | Type     | Constraints | Description           |
| ----------------- | -------- | ----------- | --------------------- |
| id                | INTEGER  | PK          | Notification ID       |
| user_id           | INTEGER  | FK, NULL    | Target user           |
| title             | TEXT     | NOT NULL    | Notification title    |
| message           | TEXT     | NOT NULL    | Notification content  |
| notification_type | TEXT     | NOT NULL    | Notification category |
| is_read           | INTEGER  | DEFAULT 0   | Read state            |
| created_at        | DATETIME | NOT NULL    | Creation time         |

Examples:

```text
new_alert
capture_started
capture_stopped
report_generated
system_warning
```

---

# 22. Relationship Details

## Users → Reports

One user can generate multiple reports.

```text
users.id
    |
    +----< reports.generated_by
```

Relationship:

**One-to-Many**

---

## Users → Notifications

One user can receive multiple notifications.

```text
users.id
    |
    +----< notifications.user_id
```

Relationship:

**One-to-Many**

---

## Devices → Packets

A device can be associated with many packet records.

```text
devices.id
    |
    +----< packets.device_id
```

Relationship:

**One-to-Many**

---

## Devices → Connections

A device can participate in multiple connections.

```text
devices.id
    |
    +----< connections.source_device_id
```

The destination can also reference another device.

---

## Devices → Alerts

A device may be associated with multiple alerts.

```text
devices.id
    |
    +----< alerts.device_id
```

---

## Devices → Behavioral Baseline

Each monitored device should have at most one active baseline.

```text
devices.id
    |
    +---- behavioral_baselines.device_id
```

Relationship:

**One-to-One**

---

## Detection Rules → Alerts

One detection rule may trigger many alerts.

```text
detection_rules.id
    |
    +----< alerts.rule_id
```

Relationship:

**One-to-Many**

---

## Alerts → Evidence

One alert can contain multiple evidence records.

```text
alerts.id
    |
    +----< alert_evidence.alert_id
```

Relationship:

**One-to-Many**

---

## Alerts → AI Insights

An alert may have one or multiple AI analysis records depending on the implementation.

```text
alerts.id
    |
    +----< ai_insights.alert_id
```

---

# 23. Indexing Strategy

High-volume tables require indexes on frequently queried fields.

## Packets

Recommended indexes:

```sql
CREATE INDEX idx_packets_timestamp
ON packets(timestamp);

CREATE INDEX idx_packets_source_ip
ON packets(source_ip);

CREATE INDEX idx_packets_destination_ip
ON packets(destination_ip);

CREATE INDEX idx_packets_protocol
ON packets(protocol);

CREATE INDEX idx_packets_device_id
ON packets(device_id);
```

---

## Alerts

```sql
CREATE INDEX idx_alerts_created_at
ON alerts(created_at);

CREATE INDEX idx_alerts_severity
ON alerts(severity);

CREATE INDEX idx_alerts_status
ON alerts(status);

CREATE INDEX idx_alerts_device_id
ON alerts(device_id);

CREATE INDEX idx_alerts_rule_id
ON alerts(rule_id);
```

---

## Connections

```sql
CREATE INDEX idx_connections_start_time
ON connections(start_time);

CREATE INDEX idx_connections_source_ip
ON connections(source_ip);

CREATE INDEX idx_connections_destination_ip
ON connections(destination_ip);
```

---

## Statistics

```sql
CREATE INDEX idx_traffic_statistics_timestamp
ON traffic_statistics(timestamp);

CREATE INDEX idx_protocol_statistics_timestamp
ON protocol_statistics(timestamp);
```

---

# 24. Data Retention Strategy

Raw packet data is high-volume and should not be retained indefinitely in the initial deployment.

Recommended starting policy:

| Data                 | Initial Retention |
| -------------------- | ----------------: |
| Raw Packet Metadata  |           30 days |
| Connections          |           90 days |
| Traffic Statistics   |          180 days |
| Protocol Statistics  |          180 days |
| Alerts               |         Long-term |
| Alert Evidence       |         Long-term |
| AI Insights          |          180 days |
| Reports              | User configurable |
| Notifications        |           90 days |
| Behavioral Baselines |    Until replaced |

These values should be configurable.

---

# 25. Raw Packet Storage Strategy

NetWatch AI should avoid storing full packet payloads by default.

Instead, the `packets` table stores normalized metadata such as:

```text
Source IP
Destination IP
Protocol
Ports
Packet Size
TCP Flags
TTL
Timestamp
```

When detailed packet evidence is required, the system can optionally retain a reference to a captured packet or PCAP segment.

This reduces storage requirements and limits unnecessary exposure of potentially sensitive payload content.

---

# 26. Database Write Strategy

High-volume packet capture can generate significantly more records than ordinary web applications.

Therefore:

```text
Packet Capture
      |
      v
In-Memory Processing
      |
      +----> Statistics
      |
      +----> Detection
      |
      v
Buffered / Batched Persistence
      |
      v
SQLite
```

The system should avoid performing a database transaction for every individual packet wherever practical.

---

# 27. Transaction Strategy

Transactions should be used for related operations.

Example:

```text
Alert Creation
      |
      +---- Alert Record
      |
      +---- Evidence Records
      |
      +---- AI Insight
```

These related operations should be committed consistently.

If an operation fails, partial alert data should not remain in the database.

---

# 28. Referential Integrity

Foreign keys should be enabled.

Example:

```sql
PRAGMA foreign_keys = ON;
```

This prevents orphaned records such as:

```text
Alert
  |
  +---- Device ID = 99999
```

when device 99999 does not exist.

---

# 29. Data Validation

Validation should happen before data reaches the database.

Examples:

## IP Address

Validate IPv4/IPv6 format.

## Ports

Valid range:

```text
0–65535
```

## Risk Score

Valid range:

```text
0–100
```

## Confidence

Valid range:

```text
0–100
```

## Severity

Allowed values:

```text
critical
high
medium
low
```

Validation should primarily be implemented at the application/schema layer and reinforced with database constraints where appropriate.

---

# 30. Security Considerations

The database layer should follow secure-development practices.

## Credentials

Passwords must never be stored in plaintext.

Only secure password hashes should be stored.

## Sensitive Data

Avoid unnecessary storage of:

* Passwords
* Full packet payloads
* Authentication tokens
* API secrets

## Database Access

The SQLite database should be accessed through the backend application rather than directly exposed to the frontend.

## SQL Injection

Use parameterized queries or an ORM/database abstraction rather than constructing SQL using untrusted string concatenation.

## Backups

Database backups should be protected because they may contain network and security information.

---

# 31. Backup Strategy

Initial local strategy:

```text
SQLite Database
      |
      v
Scheduled Backup
      |
      v
Backup File
      |
      v
Retention Policy
```

Potential implementation:

* Daily backup
* Rolling backup history
* Configurable retention

The initial version may implement manual or scheduled backup functionality depending on project scope.

---

# 32. Database Migration Strategy

Initial deployment:

```text
SQLite
```

Future deployment:

```text
SQLite
   |
   v
PostgreSQL
```

The application should isolate database-specific logic behind repositories/services where practical.

Example:

```text
Application
     |
     v
Repository Layer
     |
     v
Database Adapter
     |
     +---- SQLite
     |
     +---- PostgreSQL
```

---

# 33. Repository Layer

The backend should avoid placing SQL directly throughout business logic.

Recommended architecture:

```text
API
 |
 v
Service Layer
 |
 v
Repository Layer
 |
 v
Database
```

Example:

```text
AlertService
      |
      v
AlertRepository
      |
      v
alerts table
```

This improves testability and simplifies future database migration.

---

# 34. SQL Schema Organization

The database code should be organized separately from application logic.

Recommended structure:

```text
backend/
│
└── database/
    ├── schema.sql
    ├── indexes.sql
    ├── seed.sql
    └── migrations/
        ├── 001_initial.sql
        └── ...
```

---

# 35. Seed Data

Development environments should include safe sample data.

Example seed data:

```text
Devices
- Development Laptop
- Kali VM
- Metasploitable VM
- Router

Detection Rules
- Port Scan
- SYN Flood
- ICMP Flood
- Internal Scan
- DNS Anomaly
- Bandwidth Abuse
```

Seed data should not contain real credentials or sensitive network information.

---

# 36. Dashboard Data Mapping

The database should support the major dashboard elements.

| Dashboard Element     | Primary Data Source                |
| --------------------- | ---------------------------------- |
| Packets/sec           | traffic_statistics                 |
| Bandwidth             | traffic_statistics                 |
| Active Devices        | devices                            |
| Connections           | connections                        |
| Active Alerts         | alerts                             |
| Threat Score          | alerts / devices                   |
| Protocol Distribution | protocol_statistics                |
| Top Talkers           | packets / connections / statistics |
| Recent Alerts         | alerts                             |
| AI Insights           | ai_insights                        |
| System Health         | system_status                      |
| Notifications         | notifications                      |

---

# 37. Investigation Data Flow

When an analyst opens an alert:

```text
Alert
 |
 +---- Device
 |
 +---- Detection Rule
 |
 +---- Evidence
 |       |
 |       +---- Packets
 |       +---- Connections
 |       +---- Behavioral Data
 |       +---- ML Result
 |
 +---- AI Insight
```

This structure allows the UI to display an investigation timeline with supporting evidence.

---

# 38. Example Alert Investigation Query Flow

```text
User opens Alert #105
          |
          v
GET /alerts/105
          |
          v
Alert Service
          |
          +---- Alert
          |
          +---- Device
          |
          +---- Detection Rule
          |
          +---- Evidence
          |
          +---- AI Insight
          |
          v
Investigation Response
```

---

# 39. Database Lifecycle

```text
Application Start
      |
      v
Load Configuration
      |
      v
Initialize Database
      |
      v
Check Schema
      |
      v
Start Capture
      |
      v
Process Traffic
      |
      v
Persist Required Data
      |
      v
Cleanup Expired Data
      |
      v
Backup
```

---

# 40. Performance Considerations

The most important performance concern is packet-related data volume.

The database layer should therefore:

* Use indexes on frequently queried columns.
* Avoid unnecessary payload storage.
* Aggregate traffic statistics.
* Batch high-frequency writes where practical.
* Limit raw packet retention.
* Use pagination for packet and alert queries.
* Keep historical analytics separate from live state where practical.

---

# 41. Future Database Improvements

Potential future improvements:

* PostgreSQL
* TimescaleDB or another time-series solution
* Redis for cached dashboard metrics
* Partitioning of high-volume telemetry
* Compression and archival
* Distributed storage
* Dedicated analytics warehouse

These should only be introduced if the project grows beyond the requirements of the initial local deployment.

---

# 42. Final Entity Overview

```text
+----------------+
|     users      |
+-------+--------+
        |
        +-------------------+
        |                   |
        v                   v
+---------------+    +---------------+
|    reports    |    | notifications |
+---------------+    +---------------+


+----------------+
|    devices     |
+-------+--------+
        |
   +----+--------+----------------+
   |             |                |
   v             v                v
packets     connections      baselines
   |
   |
   v
alerts
   |
   +--------------------+
   |                    |
   v                    v
evidence             ai_insights
   |
   v
packets / connections


+---------------------+
| detection_rules     |
+----------+----------+
           |
           v
        alerts


+---------------------+
| traffic_statistics  |
+---------------------+

+---------------------+
| protocol_statistics |
+---------------------+

+---------------------+
| settings            |
+---------------------+

+---------------------+
| system_status       |
+---------------------+
```

---

# 43. Design Principles

The NetWatch AI database follows these principles:

1. Keep high-volume packet data lightweight.
2. Store normalized packet metadata rather than payloads by default.
3. Use relational relationships for security evidence.
4. Keep detection configuration data-driven.
5. Maintain device-specific behavioral baselines.
6. Keep analytics data aggregated where possible.
7. Use indexes for high-frequency queries.
8. Use retention policies for high-volume data.
9. Maintain referential integrity.
10. Keep database access behind a repository/service layer.
11. Protect network telemetry and database backups.
12. Preserve a migration path from SQLite to PostgreSQL.

---

# 44. Conclusion

The NetWatch AI database is designed to support both the monitoring and security-analysis components of the platform.

The most important design characteristic is the separation between:

```text
Raw / Normalized Telemetry
        ↓
Aggregated Statistics
        ↓
Security Findings
        ↓
Evidence
        ↓
AI Analysis
```

This allows the platform to retain useful historical information without requiring indefinite storage of every piece of network traffic.

SQLite provides a practical zero-cost database for the initial local deployment, while the modular database architecture provides a clear migration path toward PostgreSQL and higher-volume storage technologies if the platform is expanded in the future.

