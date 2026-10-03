# Vulnerability collection run

- Profile: daily
- Started: 2026-10-03T19:55:06.516676+00:00
- Completed: 2026-10-03T20:07:21.440701+00:00

## Changes

- new: 83
- quarantined: 7
- unchanged: 2286
- updated: 136

## Priorities

- INFO: 2305
- P1: 9
- P3: 198

## Source outcomes

- failed: 7
- not_modified: 84
- partial: 0
- success: 75

## Unsuccessful sources

- envoy_github (failed, json_api): records=0, parse_failures=0 — json_api: envoy_github: JSON exceeds configured limit of 100 items
- gitea_github (failed, json_api): records=0, parse_failures=0 — json_api: gitea_github: JSON exceeds configured limit of 100 items
- osv (failed, osv_global): records=0, parse_failures=0 — osv_global: osv: response exceeds 60000000 bytes
- solarwinds (failed, feed): records=0, parse_failures=0 — feed: solarwinds: 1 advisory detail fetch(es) failed: solarwinds: HTTP 404 from https://www.solarwinds.com/trust-center/security-advisories/cve-2026-28325%20
- tp_link (failed, html): records=0, parse_failures=0 — html: tp_link: configured HTML selector matched zero advisory records
- watchguard (failed, feed): records=0, parse_failures=0 — feed: watchguard: feed contained zero entries
- xerox (failed, feed): records=0, parse_failures=0 — feed: xerox: HTTP 429 from https://security.business.xerox.com/en-usdocuments/bulletins/feed/
