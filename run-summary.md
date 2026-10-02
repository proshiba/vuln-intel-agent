# Vulnerability collection run

- Profile: daily
- Started: 2026-10-02T19:09:26.709166+00:00
- Completed: 2026-10-02T19:22:45.007681+00:00

## Changes

- new: 371
- quarantined: 7
- unchanged: 2553
- updated: 169

## Priorities

- INFO: 2848
- P1: 42
- P2: 3
- P3: 207

## Source outcomes

- failed: 7
- not_modified: 11
- partial: 0
- success: 148

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
