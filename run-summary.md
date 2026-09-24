# Vulnerability collection run

- Profile: daily
- Started: 2026-09-24T19:09:31.608991+00:00
- Completed: 2026-09-24T19:20:04.004862+00:00

## Changes

- new: 221
- quarantined: 7
- unchanged: 2076
- updated: 192

## Priorities

- INFO: 2241
- P1: 8
- P2: 3
- P3: 244

## Source outcomes

- failed: 7
- not_modified: 72
- partial: 0
- success: 87

## Unsuccessful sources

- envoy_github (failed, json_api): records=0, parse_failures=0 — json_api: envoy_github: JSON exceeds configured limit of 100 items
- gitea_github (failed, json_api): records=0, parse_failures=0 — json_api: gitea_github: JSON exceeds configured limit of 100 items
- lenovo (failed, html): records=0, parse_failures=0 — html: lenovo: HTTP 403 from https://pcsupport.lenovo.com/us/en/product_security/home
- osv (failed, osv_global): records=0, parse_failures=0 — osv_global: osv: response exceeds 60000000 bytes
- solarwinds (failed, feed): records=0, parse_failures=0 — feed: solarwinds: 1 advisory detail fetch(es) failed: solarwinds: HTTP 404 from https://www.solarwinds.com/trust-center/security-advisories/cve-2026-28325%20
- tp_link (failed, html): records=0, parse_failures=0 — html: tp_link: configured HTML selector matched zero advisory records
- watchguard (failed, feed): records=0, parse_failures=0 — feed: watchguard: 10 advisory detail fetch(es) failed: watchguard: host is not allowed: psirt.watchguard.com
