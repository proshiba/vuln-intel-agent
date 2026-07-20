# Repository instructions

## Vulnerability collection and daily report

Use the project virtual environment (`.venv/bin/...`) and generate into `staging/` first. The
normal full run collects all 160 enabled sources. Nine of those sources use the browser
collector, so install the browser extra and Chromium in a new environment before collecting:

```bash
.venv/bin/python -m pip install -e '.[dev,ai,browser]'
.venv/bin/python -m playwright install --with-deps chromium
```

Then run:

```bash
.venv/bin/vulnwatch config validate
.venv/bin/vulnwatch collect --profile daily --since 90d --output staging
.venv/bin/vulnwatch summarize --root staging
```

After `collect`, verify `run-manifest.json.source_outcomes` before summarizing. A daily run must have
exactly one outcome for every enabled source (currently 160). `success` and `not_modified` are
acceptable; if any outcome is missing, `failed`, or `partial`, stop before summary, report, or
publish, inspect its endpoint/count/error fields and `quarantine/`, then fix or retry the source.
`vulnwatch validate` independently rejects incomplete or unsuccessful outcomes; use it only as a
failure check until collection is complete. The scheduled workflow performs the same completeness
check before handing off generated data.

Sources with `role: coverage` are intentionally written to advisory storage and the `vulndb` ledger
without creating daily report change rows. Do not mistake their absence from a report table for a
collection failure; use `source_outcomes` to assess collection completeness.

The global OSV source has an explicit one-hour bootstrap window on its first successful activation;
the normal 90-day window would otherwise require hundreds of thousands of detail downloads. After
that activation, it collects every delta newer than its tracked `last_success_at`. Do not delete the
OSV source state unless intentionally reactivating it, and treat the bootstrap boundary as a known
historical-coverage limit rather than claiming that the first run backfilled all OSV history.

After collection, inspect the current `run-manifest.json`, advisory JSON, and their public source
URLs. When the manifest contains new, updated, or withdrawn advisories, use AI to write both required
Japanese section summaries, then pass them while generating the report:

```bash
.venv/bin/vulnwatch report --root staging \
  --critical-summary '<Critical全件の日本語AIサマリ>' \
  --exploitation-summary '<悪用済み・PoC公開済みの日本語AIサマリ>'
```

`vulnwatch summarize` also generates these section summaries automatically when
`OPENAI_API_KEY` and `LLM_MODEL` are configured. An interactive agent must review a locally generated
summary against the current facts; scheduled results are exposed in the bot PR for review before
merge. Running `vulnwatch report` without the two options is allowed only when a current successful
summary sidecar already exists, or when the manifest has no reportable changes. In the latter case,
generate the deterministic no-change report; no section summary sidecar is required.

Summary requirements:

- Write 2–4 concise Japanese sentences for each section, using only facts in the current generated
  data and cited public sources. Never infer missing facts.
- The Critical summary covers every Critical advisory in the current report's
  new/updated/withdrawn change set, regardless of CVSS availability or exploitation status. State
  advisory counts, notable vendors/products, exploitation/PoC counts, and the practical review focus
  when supported by the data.
- The exploitation summary covers the union of `悪用済み` and `PoC公開済み` across all severities.
  Distinguish the two states, explain their overlap, and do not treat a public PoC as proof of
  exploitation.
- Counts in the report are advisory counts, not unique CVE counts. Use `アドバイザリ件` when the
  distinction matters.
- Do not edit generated table values or rows manually. Regenerate the sidecar and Markdown together
  whenever collection facts change. When reportable changes exist, missing, stale, skipped, failed,
  refused, or placeholder AI summaries must not be published.

Then validate and publish the complete generated tree:

```bash
.venv/bin/vulnwatch validate --root staging
.venv/bin/vulnwatch publish --root staging --repository .
git add -A -- data reports state quarantine vulndb run-manifest.json run-summary.md
```

All generated collection data, report Markdown, report-summary JSON, and the `vulndb/` ledger
(`index.csv`, `registry.json`, and per-vulnerability YAML under `vulns/<vendor>/<year>/<month>/`)
are Git-managed artifacts. Never add credentials, tokens, `.env` files, caches, or the temporary
`staging/` tree. GitHub tokens are used only for reading public repository/API data and must not
appear in logs or generated files.

`config/sources.yaml` enables `catalog_runtime`. A catalog entry that omits an explicit `enabled`
field therefore becomes an active, bounded official-web source automatically. Prefer a verified
machine-readable endpoint and source-specific runtime settings when available, and treat every new
catalog entry as part of the next full daily run.

Scheduled runs are split between systems: GitHub Actions collects and hands the raw tree to a Claude
Code routine over a webhook; the routine writes the summaries and report and pushes
`bot/vulnwatch-daily`, which the auto-merge workflow verifies and merges into `main`.

Before handing off a code change, run the relevant tests plus:

```bash
.venv/bin/pytest
.venv/bin/ruff check .
.venv/bin/mypy src
```
