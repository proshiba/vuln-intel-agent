# Vulnerability collection run

- Profile: daily
- Started: 2026-09-12T19:07:36.233122+00:00
- Completed: 2026-09-12T19:16:47.679639+00:00

## Changes

- new: 56
- quarantined: 7
- unchanged: 2336
- updated: 132

## Priorities

- INFO: 2283
- P1: 37
- P2: 3
- P3: 208

## Source outcomes

- failed: 7
- not_modified: 78
- partial: 0
- success: 81

## Unsuccessful sources

- envoy_github (failed, json_api): records=0, parse_failures=0 — json_api: envoy_github: JSON exceeds configured limit of 100 items
- gitea_github (failed, json_api): records=0, parse_failures=0 — json_api: gitea_github: JSON exceeds configured limit of 100 items
- github_enterprise (failed, html): records=0, parse_failures=0 — html: github_enterprise: configured HTML selector matched zero advisory records
- mikrotik (failed, html): records=0, parse_failures=0 — html: mikrotik: configured HTML selector matched zero advisory records
- osv (failed, osv_global): records=0, parse_failures=0 — osv_global: osv: response exceeds 60000000 bytes
- tp_link (failed, html): records=0, parse_failures=0 — html: tp_link: 2 advisory detail fetch(es) failed: tp_link: host is not allowed: support.omadanetworks.com
- watchguard (failed, feed): records=0, parse_failures=0 — feed: watchguard: 10 advisory detail fetch(es) failed: watchguard: host is not allowed: psirt.watchguard.com
