# Vulnerability collection run

- Profile: daily
- Started: 2026-09-23T19:09:40.996208+00:00
- Completed: 2026-09-23T19:22:56.448466+00:00

## Changes

- new: 143
- quarantined: 6
- unchanged: 2377
- updated: 189

## Priorities

- INFO: 2429
- P1: 45
- P2: 3
- P3: 238

## Source outcomes

- failed: 6
- not_modified: 72
- partial: 0
- success: 88

## Unsuccessful sources

- envoy_github (failed, json_api): records=0, parse_failures=0 — json_api: envoy_github: JSON exceeds configured limit of 100 items
- gitea_github (failed, json_api): records=0, parse_failures=0 — json_api: gitea_github: JSON exceeds configured limit of 100 items
- osv (failed, osv_global): records=0, parse_failures=0 — osv_global: osv: response exceeds 60000000 bytes
- solarwinds (failed, feed): records=0, parse_failures=0 — feed: solarwinds: 1 advisory detail fetch(es) failed: solarwinds: HTTP 404 from https://www.solarwinds.com/trust-center/security-advisories/cve-2026-28325%20
- tp_link (failed, html): records=0, parse_failures=0 — html: tp_link: configured HTML selector matched zero advisory records
- watchguard (failed, feed): records=0, parse_failures=0 — feed: watchguard: 10 advisory detail fetch(es) failed: watchguard: host is not allowed: psirt.watchguard.com
