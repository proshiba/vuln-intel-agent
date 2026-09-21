# Vulnerability collection run

- Profile: daily
- Started: 2026-09-21T19:09:36.782577+00:00
- Completed: 2026-09-21T19:23:22.278439+00:00

## Changes

- new: 178
- quarantined: 6
- unchanged: 2110
- updated: 209

## Priorities

- INFO: 2213
- P1: 42
- P2: 3
- P3: 245

## Source outcomes

- failed: 6
- not_modified: 77
- partial: 0
- success: 83

## Unsuccessful sources

- envoy_github (failed, json_api): records=0, parse_failures=0 — json_api: envoy_github: JSON exceeds configured limit of 100 items
- gitea_github (failed, json_api): records=0, parse_failures=0 — json_api: gitea_github: JSON exceeds configured limit of 100 items
- github_enterprise (failed, html): records=0, parse_failures=0 — html: github_enterprise: configured HTML selector matched zero advisory records
- osv (failed, osv_global): records=0, parse_failures=0 — osv_global: osv: response exceeds 60000000 bytes
- tp_link (failed, html): records=0, parse_failures=0 — html: tp_link: configured HTML selector matched zero advisory records
- watchguard (failed, feed): records=0, parse_failures=0 — feed: watchguard: 10 advisory detail fetch(es) failed: watchguard: host is not allowed: psirt.watchguard.com
