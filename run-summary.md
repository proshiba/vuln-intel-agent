# Vulnerability collection run

- Profile: daily
- Started: 2026-09-07T19:08:18.970028+00:00
- Completed: 2026-09-07T19:18:25.706277+00:00

## Changes

- new: 77
- quarantined: 6
- unchanged: 1962
- updated: 224

## Priorities

- INFO: 2039
- P1: 4
- P3: 226

## Source outcomes

- failed: 6
- not_modified: 82
- partial: 0
- success: 78

## Unsuccessful sources

- envoy_github (failed, json_api): records=0, parse_failures=0 — json_api: envoy_github: JSON exceeds configured limit of 100 items
- gitea_github (failed, json_api): records=0, parse_failures=0 — json_api: gitea_github: JSON exceeds configured limit of 100 items
- mikrotik (failed, html): records=0, parse_failures=0 — html: mikrotik: configured HTML selector matched zero advisory records
- osv (failed, osv_global): records=0, parse_failures=0 — osv_global: osv: response exceeds 60000000 bytes
- tp_link (failed, html): records=0, parse_failures=0 — html: tp_link: 1 advisory detail fetch(es) failed: tp_link: host is not allowed: support.omadanetworks.com
- watchguard (failed, feed): records=0, parse_failures=0 — feed: watchguard: 10 advisory detail fetch(es) failed: watchguard: host is not allowed: psirt.watchguard.com
