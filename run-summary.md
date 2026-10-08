# Vulnerability collection run

- Profile: daily
- Started: 2026-10-08T19:12:23.359241+00:00
- Completed: 2026-10-08T19:21:58.244889+00:00

## Changes

- new: 167
- quarantined: 7
- unchanged: 2664
- updated: 195

## Priorities

- INFO: 2810
- P1: 40
- P2: 2
- P3: 181

## Source outcomes

- failed: 7
- not_modified: 66
- partial: 0
- success: 93

## Unsuccessful sources

- envoy_github (failed, json_api): records=0, parse_failures=0 — json_api: envoy_github: JSON exceeds configured limit of 100 items
- gitea_github (failed, json_api): records=0, parse_failures=0 — json_api: gitea_github: JSON exceeds configured limit of 100 items
- nist_nvd (failed, nvd): records=0, parse_failures=0 — nvd: nist_nvd: NVD response has invalid resultsPerPage
- osv (failed, osv_global): records=0, parse_failures=0 — osv_global: osv: response exceeds 60000000 bytes
- solarwinds (failed, feed): records=0, parse_failures=0 — feed: solarwinds: 1 advisory detail fetch(es) failed: solarwinds: HTTP 404 from https://www.solarwinds.com/trust-center/security-advisories/cve-2026-28325%20
- tp_link (failed, html): records=0, parse_failures=0 — html: tp_link: configured HTML selector matched zero advisory records
- watchguard (failed, feed): records=0, parse_failures=0 — feed: watchguard: feed contained zero entries
