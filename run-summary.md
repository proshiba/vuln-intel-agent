# Vulnerability collection run

- Profile: daily
- Started: 2026-09-26T19:09:14.794065+00:00
- Completed: 2026-09-26T19:23:13.038026+00:00

## Changes

- new: 40
- quarantined: 7
- unchanged: 2225
- updated: 154

## Priorities

- INFO: 2154
- P1: 45
- P3: 227

## Source outcomes

- failed: 7
- not_modified: 83
- partial: 0
- success: 76

## Unsuccessful sources

- envoy_github (failed, json_api): records=0, parse_failures=0 — json_api: envoy_github: JSON exceeds configured limit of 100 items
- gitea_github (failed, json_api): records=0, parse_failures=0 — json_api: gitea_github: JSON exceeds configured limit of 100 items
- lenovo (failed, html): records=0, parse_failures=0 — html: lenovo: HTTP 403 from https://pcsupport.lenovo.com/us/en/product_security/home
- osv (failed, osv_global): records=0, parse_failures=0 — osv_global: osv: response exceeds 60000000 bytes
- solarwinds (failed, feed): records=0, parse_failures=0 — feed: solarwinds: 1 advisory detail fetch(es) failed: solarwinds: HTTP 404 from https://www.solarwinds.com/trust-center/security-advisories/cve-2026-28325%20
- tp_link (failed, html): records=0, parse_failures=0 — html: tp_link: configured HTML selector matched zero advisory records
- watchguard (failed, feed): records=0, parse_failures=0 — feed: watchguard: 10 advisory detail fetch(es) failed: watchguard: host is not allowed: psirt.watchguard.com
