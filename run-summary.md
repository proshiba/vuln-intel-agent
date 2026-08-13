# Vulnerability collection run

- Profile: daily
- Started: 2026-08-13T19:25:18.484087+00:00
- Completed: 2026-08-13T19:35:32.098537+00:00

## Changes

- new: 231
- quarantined: 3
- unchanged: 2045
- updated: 524

## Priorities

- INFO: 2586
- P1: 5
- P2: 1
- P3: 211

## Source outcomes

- failed: 3
- not_modified: 75
- partial: 0
- success: 88

## Unsuccessful sources

- dell_technologies (failed, browser): records=0, parse_failures=0 — browser: dell_technologies: browser navigation failed: Page.wait_for_selector: Timeout 30000ms exceeded.
Call log:
  - waiting for locator("a[href*='/support/kbdoc/'][href*='/dsa-']")

- osv (failed, osv_global): records=0, parse_failures=0 — osv_global: osv: OSV modified index is not sorted newest-first
- tp_link (failed, html): records=0, parse_failures=0 — html: tp_link: 2 advisory detail fetch(es) failed: tp_link: host is not allowed: support.omadanetworks.com
