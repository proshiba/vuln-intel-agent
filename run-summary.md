# Vulnerability collection run

- Profile: daily
- Started: 2026-09-04T19:08:23.588853+00:00
- Completed: 2026-09-04T19:20:10.646899+00:00

## Changes

- new: 103
- quarantined: 6
- unchanged: 2190
- updated: 238

## Priorities

- INFO: 2276
- P1: 40
- P3: 221

## Source outcomes

- failed: 6
- not_modified: 78
- partial: 0
- success: 82

## Unsuccessful sources

- envoy_github (failed, json_api): records=0, parse_failures=0 — json_api: envoy_github: JSON exceeds configured limit of 100 items
- gitea_github (failed, json_api): records=0, parse_failures=0 — json_api: gitea_github: JSON exceeds configured limit of 100 items
- mikrotik (failed, html): records=0, parse_failures=0 — html: mikrotik: configured HTML selector matched zero advisory records
- osv (failed, osv_global): records=0, parse_failures=0 — osv_global: osv: OSV delta exceeds configured detail fetch limit of 20000 items
- tp_link (failed, html): records=0, parse_failures=0 — html: tp_link: 1 advisory detail fetch(es) failed: tp_link: host is not allowed: support.omadanetworks.com
- watchguard (failed, feed): records=0, parse_failures=0 — feed: watchguard: 10 advisory detail fetch(es) failed: watchguard: host is not allowed: psirt.watchguard.com
