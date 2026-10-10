# Vulnerability collection run

- Profile: daily
- Started: 2026-10-10T19:08:42.136580+00:00
- Completed: 2026-10-10T19:18:27.501671+00:00

## Changes

- new: 119
- quarantined: 7
- unchanged: 2189
- updated: 258

## Priorities

- INFO: 2387
- P1: 8
- P3: 178

## Source outcomes

- failed: 7
- not_modified: 85
- partial: 0
- success: 74

## Unsuccessful sources

- dell_technologies (failed, browser): records=0, parse_failures=0 — browser: dell_technologies: browser HTTP 403 from https://www.dell.com/support/security/en-us
- envoy_github (failed, json_api): records=0, parse_failures=0 — json_api: envoy_github: JSON exceeds configured limit of 100 items
- gitea_github (failed, json_api): records=0, parse_failures=0 — json_api: gitea_github: JSON exceeds configured limit of 100 items
- osv (failed, osv_global): records=0, parse_failures=0 — osv_global: osv: response exceeds 60000000 bytes
- solarwinds (failed, feed): records=0, parse_failures=0 — feed: solarwinds: 1 advisory detail fetch(es) failed: solarwinds: HTTP 404 from https://www.solarwinds.com/trust-center/security-advisories/cve-2026-28325%20
- tp_link (failed, html): records=0, parse_failures=0 — html: tp_link: configured HTML selector matched zero advisory records
- watchguard (failed, feed): records=0, parse_failures=0 — feed: watchguard: feed contained zero entries
