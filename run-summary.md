# Vulnerability collection run

- Profile: daily
- Started: 2026-09-19T19:08:21.685917+00:00
- Completed: 2026-09-19T19:20:42.456463+00:00

## Changes

- new: 81
- quarantined: 6
- unchanged: 2189
- updated: 129

## Priorities

- INFO: 2160
- P1: 36
- P3: 209

## Source outcomes

- failed: 6
- not_modified: 81
- partial: 0
- success: 79

## Unsuccessful sources

- envoy_github (failed, json_api): records=0, parse_failures=0 — json_api: envoy_github: JSON exceeds configured limit of 100 items
- gitea_github (failed, json_api): records=0, parse_failures=0 — json_api: gitea_github: JSON exceeds configured limit of 100 items
- github_enterprise (failed, html): records=0, parse_failures=0 — html: github_enterprise: configured HTML selector matched zero advisory records
- osv (failed, osv_global): records=0, parse_failures=0 — osv_global: osv: response exceeds 60000000 bytes
- tp_link (failed, html): records=0, parse_failures=0 — html: tp_link: configured HTML selector matched zero advisory records
- watchguard (failed, feed): records=0, parse_failures=0 — feed: watchguard: 10 advisory detail fetch(es) failed: watchguard: host is not allowed: psirt.watchguard.com
