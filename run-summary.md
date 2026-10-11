# Vulnerability collection run

- Profile: daily
- Started: 2026-10-11T19:09:42.088702+00:00
- Completed: 2026-10-11T19:24:48.988190+00:00

## Changes

- new: 47
- quarantined: 7
- unchanged: 2403
- updated: 130

## Priorities

- INFO: 2404
- P1: 8
- P3: 175

## Source outcomes

- failed: 7
- not_modified: 84
- partial: 0
- success: 75

## Unsuccessful sources

- axis_communications (failed, html): records=0, parse_failures=0 — html: axis_communications: network failure: 
- envoy_github (failed, json_api): records=0, parse_failures=0 — json_api: envoy_github: JSON exceeds configured limit of 100 items
- gitea_github (failed, json_api): records=0, parse_failures=0 — json_api: gitea_github: JSON exceeds configured limit of 100 items
- osv (failed, osv_global): records=0, parse_failures=0 — osv_global: osv: response exceeds 60000000 bytes
- solarwinds (failed, feed): records=0, parse_failures=0 — feed: solarwinds: 1 advisory detail fetch(es) failed: solarwinds: HTTP 404 from https://www.solarwinds.com/trust-center/security-advisories/cve-2026-28325%20
- tp_link (failed, html): records=0, parse_failures=0 — html: tp_link: configured HTML selector matched zero advisory records
- watchguard (failed, feed): records=0, parse_failures=0 — feed: watchguard: feed contained zero entries
