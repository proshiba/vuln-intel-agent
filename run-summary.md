# Vulnerability collection run

- Profile: daily
- Started: 2026-09-20T19:07:59.572353+00:00
- Completed: 2026-09-20T19:17:44.074943+00:00

## Changes

- new: 6
- quarantined: 6
- unchanged: 2171
- updated: 116

## Priorities

- INFO: 2071
- P1: 8
- P2: 3
- P3: 217

## Source outcomes

- failed: 6
- not_modified: 85
- partial: 0
- success: 75

## Unsuccessful sources

- envoy_github (failed, json_api): records=0, parse_failures=0 — json_api: envoy_github: JSON exceeds configured limit of 100 items
- gitea_github (failed, json_api): records=0, parse_failures=0 — json_api: gitea_github: JSON exceeds configured limit of 100 items
- github_enterprise (failed, html): records=0, parse_failures=0 — html: github_enterprise: configured HTML selector matched zero advisory records
- osv (failed, osv_global): records=0, parse_failures=0 — osv_global: osv: response exceeds 60000000 bytes
- tp_link (failed, html): records=0, parse_failures=0 — html: tp_link: configured HTML selector matched zero advisory records
- watchguard (failed, feed): records=0, parse_failures=0 — feed: watchguard: 10 advisory detail fetch(es) failed: watchguard: host is not allowed: psirt.watchguard.com
