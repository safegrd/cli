---
name: check-backups
description: Report on SafeGrd backups across an organization, covering surfaces whose backups are late, drills that failed, surfaces never proven to restore, and hosted storage use. Use when the user asks whether their backups are working, for a backup status, or what needs attention.
---

# Check SafeGrd backups

1. Call `list_organizations`. For each organization the user cares about, call
   `drill_stats` (pass rate, failed drills, surfaces never proven) and `storage_usage`
   (hosted storage used against the quota).
2. Call `list_surfaces`. Pass `next_cursor` back as `cursor` until it is absent, so no
   surface is missed.
3. For each surface, compare `last_backup_at` with its `schedule` and `last_heartbeat`, and
   read its drill and alert state. Call `list_drills` with `limit: 1` for any surface whose
   last drill failed.

Report only what needs attention, worst first:

- a failed drill, with the assertion that failed
- a surface with no backup for longer than its schedule, or a host that stopped checking in
- a surface never drilled, meaning its backups have never been restored
- hosted storage above 80% of its quota

Then one line for the rest ("12 other surfaces backed up and drilled on schedule").

For each problem, name the next step. If it needs the host, give the command to run there
(`safegrd status`, `safegrd doctor`, `safegrd backup --surface <id>`). If a drill would
answer the question, offer `request_drill`.
