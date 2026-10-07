# Vulnerability collection run

- Profile: daily
- Started: 2026-10-07T19:10:57.527101+00:00
- Completed: 2026-10-07T19:20:17.810812+00:00

## Changes

- new: 208
- quarantined: 6
- unchanged: 2427
- updated: 246

## Priorities

- INFO: 2708
- P1: 8
- P3: 171

## Source outcomes

- failed: 6
- not_modified: 74
- partial: 0
- success: 86

## Unsuccessful sources

- envoy_github (failed, json_api): records=0, parse_failures=0 — json_api: envoy_github: JSON exceeds configured limit of 100 items
- gitea_github (failed, json_api): records=0, parse_failures=0 — json_api: gitea_github: JSON exceeds configured limit of 100 items
- osv (failed, osv_global): records=0, parse_failures=0 — osv_global: osv: response exceeds 60000000 bytes
- solarwinds (failed, feed): records=0, parse_failures=0 — feed: solarwinds: 1 advisory detail fetch(es) failed: solarwinds: HTTP 404 from https://www.solarwinds.com/trust-center/security-advisories/cve-2026-28325%20
- tp_link (failed, html): records=0, parse_failures=0 — html: tp_link: configured HTML selector matched zero advisory records
- watchguard (failed, feed): records=0, parse_failures=0 — feed: watchguard: feed contained zero entries
