---
name: backup-before-risky-change
description: Take a locked SafeGrd backup of a database and prove it restores before a migration, a schema change, a bulk delete, a reset or any command that can lose data. Use when the user is about to change a production or staging database, or asks whether they have a recent backup that restores.
---

# Back up, and prove it restores, before a risky change

A backup that has not been restored is a guess. Before the change, get a snapshot taken
after the last write that matters, locked so nothing can delete it, and a Fire Drill that
restored it. Do not run the risky command until that is done, or until the user says to go
ahead without it.

## 1. Find the surface

1. Call `list_organizations`, then `list_surfaces`. A surface is one database, file tree
   or mailbox. Match the user's database by `name`, `database_name` and `surface_type`.
2. If more than one matches, ask which one. Two databases of the same engine are common
   (production and staging, or MySQL and MariaDB).

## 2. Read where it stands

- `get_surface`: `last_backup_at`, `last_verified_at`, `last_heartbeat`, `schedule`.
- `list_snapshots` with `limit: 1`: the newest snapshot, its `status`, and
  `worm_retention_until` (locked until). A snapshot with `worm_mode` `NONE` is not locked.
- `list_drills` with `limit: 1`: the newest Fire Drill, its `status` and the snapshot it
  restored.

Tell the user what you found in a few lines before you ask for anything.

## 3. Take a fresh backup

Choose the first that applies:

- **The SafeGrd CLI is on this machine and the surface is in its config** (`safegrd daemon
  status` lists its id): run `safegrd guard --surface <id> -- <the risky command>`. It
  backs up, checks the snapshot is locked, and only then runs the command. A refusal exits
  3 and says why.
  Use `safegrd backup --surface <id>` instead when the user wants the backup now and the
  change later.
- **Otherwise:** call `request_backup` with the surface's `node_id`, and read the answer:
  - Accepted: the host's daemon runs it at its next check-in, or SafeGrd queues it for a
    surface SafeGrd backs up. Call `list_snapshots` with `limit: 1` about once a minute
    until a snapshot newer than the request appears. A request is not a backup.
  - `HTTP 409`, no daemon on the host: nothing will pick the request up. Ask the user to
    run `safegrd backup --surface <id>` on that host, then continue from step 4.
  - `HTTP 429`: a backup was taken less than an hour ago. Each one is locked and stored
    until it expires, so requests are at most hourly. Tell the user when it was taken, and
    ask whether anything written since then matters.

## 4. Prove it restores

Call `request_drill` with the same `node_id`, then `list_drills` with `limit: 1` about once
a minute until a drill of the new snapshot appears.

- `passed`: report the assertions it checked (tables and rows restored, digests).
- `failed`: stop. Report the failing assertion and tell the user not to proceed.
- `HTTP 429`: the plan's drill cadence is used up until the time the answer gives. Report
  the newest passed drill and which snapshot it restored, and say the new snapshot is not
  yet proven.

## 5. Report

One fact per line: the surface, the snapshot id, when it was taken, locked until when, and
the drill result. Then say whether it is safe to proceed. Anything written after the
snapshot is not in it, so the user should pause writes or accept losing them.
