# Vulnerability collection run

- Profile: daily
- Started: 2026-09-17T19:09:12.176843+00:00
- Completed: 2026-09-17T19:21:34.938955+00:00

## Changes

- new: 238
- quarantined: 6
- unchanged: 2050
- updated: 156

## Priorities

- INFO: 2202
- P1: 38
- P2: 3
- P3: 207

## Source outcomes

- failed: 6
- not_modified: 76
- partial: 0
- success: 84

## Unsuccessful sources

- envoy_github (failed, json_api): records=0, parse_failures=0 — json_api: envoy_github: JSON exceeds configured limit of 100 items
- gitea_github (failed, json_api): records=0, parse_failures=0 — json_api: gitea_github: JSON exceeds configured limit of 100 items
- github_enterprise (failed, html): records=0, parse_failures=0 — html: github_enterprise: configured HTML selector matched zero advisory records
- osv (failed, osv_global): records=0, parse_failures=0 — osv_global: osv: response exceeds 60000000 bytes
- tp_link (failed, html): records=0, parse_failures=0 — html: tp_link: 2 advisory detail fetch(es) failed: tp_link: host is not allowed: support.omadanetworks.com
- watchguard (failed, feed): records=0, parse_failures=0 — feed: watchguard: 10 advisory detail fetch(es) failed: watchguard: host is not allowed: psirt.watchguard.com
