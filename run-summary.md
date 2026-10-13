# Vulnerability collection run

- Profile: daily
- Started: 2026-10-13T19:09:59.173775+00:00
- Completed: 2026-10-13T19:26:23.364338+00:00

## Changes

- new: 184
- quarantined: 7
- unchanged: 2468
- updated: 152

## Priorities

- INFO: 2585
- P1: 39
- P2: 2
- P3: 185

## Source outcomes

- failed: 7
- not_modified: 71
- partial: 0
- success: 88

## Unsuccessful sources

- dell_technologies (failed, browser): records=0, parse_failures=0 — browser: dell_technologies: browser navigation failed: Page.wait_for_selector: Timeout 30000ms exceeded.
Call log:
  - waiting for locator("a[href*='/support/kbdoc/'][href*='/dsa-']")

- envoy_github (failed, json_api): records=0, parse_failures=0 — json_api: envoy_github: JSON exceeds configured limit of 100 items
- gitea_github (failed, json_api): records=0, parse_failures=0 — json_api: gitea_github: JSON exceeds configured limit of 100 items
- osv (failed, osv_global): records=0, parse_failures=0 — osv_global: osv: response exceeds 60000000 bytes
- solarwinds (failed, feed): records=0, parse_failures=0 — feed: solarwinds: 1 advisory detail fetch(es) failed: solarwinds: HTTP 404 from https://www.solarwinds.com/trust-center/security-advisories/cve-2026-28325%20
- tp_link (failed, html): records=0, parse_failures=0 — html: tp_link: configured HTML selector matched zero advisory records
- watchguard (failed, feed): records=0, parse_failures=0 — feed: watchguard: feed contained zero entries
