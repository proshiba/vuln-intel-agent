# Vulnerability collection run

- Profile: daily
- Started: 2026-08-31T19:08:20.800671+00:00
- Completed: 2026-08-31T19:18:43.555484+00:00

## Changes

- new: 123
- quarantined: 5
- unchanged: 2132
- updated: 176

## Priorities

- INFO: 2178
- P1: 40
- P3: 218

## Source outcomes

- failed: 5
- not_modified: 77
- partial: 0
- success: 84

## Unsuccessful sources

- envoy_github (failed, json_api): records=0, parse_failures=0 — json_api: envoy_github: JSON exceeds configured limit of 100 items
- gitea_github (failed, json_api): records=0, parse_failures=0 — json_api: gitea_github: JSON exceeds configured limit of 100 items
- osv (failed, osv_global): records=0, parse_failures=0 — osv_global: osv: OSV modified index is not sorted newest-first
- tp_link (failed, html): records=0, parse_failures=0 — html: tp_link: 1 advisory detail fetch(es) failed: tp_link: host is not allowed: support.omadanetworks.com
- watchguard (failed, feed): records=0, parse_failures=0 — feed: watchguard: 10 advisory detail fetch(es) failed: watchguard: host is not allowed: psirt.watchguard.com
