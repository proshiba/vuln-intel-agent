# Vulnerability collection run

- Profile: daily
- Started: 2026-09-01T19:09:33.867489+00:00
- Completed: 2026-09-01T19:24:37.582886+00:00

## Changes

- new: 129
- quarantined: 6
- unchanged: 2125
- updated: 201

## Priorities

- INFO: 2230
- P1: 4
- P3: 227

## Source outcomes

- failed: 6
- not_modified: 74
- partial: 0
- success: 86

## Unsuccessful sources

- envoy_github (failed, json_api): records=0, parse_failures=0 — json_api: envoy_github: JSON exceeds configured limit of 100 items
- gitea_github (failed, json_api): records=0, parse_failures=0 — json_api: gitea_github: JSON exceeds configured limit of 100 items
- osv (failed, osv_global): records=0, parse_failures=0 — osv_global: osv: OSV delta exceeds configured detail fetch limit of 20000 items
- qnap (failed, feed): records=0, parse_failures=0 — feed: qnap: HTTP 405 from https://www.qnap.com/en-us/security-advisory/feed
- tp_link (failed, html): records=0, parse_failures=0 — html: tp_link: 1 advisory detail fetch(es) failed: tp_link: host is not allowed: support.omadanetworks.com
- watchguard (failed, feed): records=0, parse_failures=0 — feed: watchguard: 10 advisory detail fetch(es) failed: watchguard: host is not allowed: psirt.watchguard.com
