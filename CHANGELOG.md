# Changelog

All notable changes to this project. The project has no versioned releases,
so entries are grouped by date, newest first. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

## 2026-10-06

### Added
- **Device alerts:** an info alert when a known device has been missing from
  scans for 5 minutes (`device_left`), and another when it comes back
  (`device_returned`). Empty scans are ignored, and the first scan after
  startup is silent, to avoid alert storms.
- **Port finding lifecycle:** findings now have `status` (`open`/`closed`) and
  `closed_at`. A finding closes when a scan covers its port and the port is no
  longer open, and a reopened port alerts again. Existing databases are
  migrated automatically.
- **Security Findings panel** in the dashboard, with severity badges for the
  critical/high/medium/low tiers and dimmed closed findings.
- `NETMON_THREADS` setting for the number of server worker threads (default 8).
- README: "Running locally" and "Alert types" sections, and the `/api/findings`
  endpoint.

### Changed
- Device discovery and port scanning run in their own thread, so slow scans no
  longer delay the 2-second traffic sampling.
- At most 2 scans run at once; extra requests get `429` with `Retry-After`.
- Hostname lookups run in parallel with a 0.5s limit instead of one by one.
- Traffic and alert tables are pruned every 100 inserts instead of on every
  insert.
- `/api/findings` ETag now covers the whole payload, so updates to a row are
  no longer hidden behind a stale `304`. ETag logic is shared by all routes.

### Fixed
- **Security:** `/api/ports/scan` now scans the IP that passed the
  private-address check instead of resolving the hostname a second time
  (DNS rebinding).
- Exceptions in the monitor loop are logged instead of silently swallowed, and
  logging is now configured at startup so alerts show in the console.
- Removed `socket.setdefaulttimeout`, which changed the timeout for every
  socket in the process.
- Removed `data/*.db-shm` and `data/*.db-wal` from version control and
  ignored `data/*.db*`. Earlier commits still contain those files.
- Repaired three stale alert tests and added tests for the changes above.
- MD5 ETags are marked `usedforsecurity=False` for FIPS-restricted systems.

## 2026-09-30

### Added
- Tiered alert severity for risky ports, host grouping, and a scrollable
  alerts panel with a summary footer.
- Persistent `port_findings` table, so port alerts are deduplicated across
  restarts, and separate findings and event-log views.

### Fixed
- Deduplicated risky-port and traffic-spike alerts (traffic spikes have a
  5-minute cooldown).

## 2026-09-29

### Fixed
- Duplicate CORS environment setting, silent monitor errors, and hostname
  resolution speed.

## 2026-08-31

### Changed
- Frontend prepared for Vercel deployment, and Flask routing fixed for Vercel.

## 2026-07-22

### Added
- Initial release: live traffic monitoring, device discovery, port scanning,
  rule-based alerts, login, and SQLite history.
- MIT license and a GitHub Actions workflow that runs the tests.
