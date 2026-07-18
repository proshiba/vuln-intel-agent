# Repository instructions

## Vulnerability collection and daily report

Use the project virtual environment (`.venv/bin/...`) and generate into `staging/` first. The
normal full run is:

```bash
.venv/bin/vulnwatch config validate
.venv/bin/vulnwatch collect --profile daily --since 90d --output staging
.venv/bin/vulnwatch summarize --root staging
```

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
git add -A -- data reports state quarantine run-manifest.json run-summary.md
```

All generated collection data, report Markdown, and report-summary JSON are Git-managed artifacts.
Never add credentials, tokens, `.env` files, caches, or the temporary `staging/` tree. GitHub tokens
are used only for reading public repository/API data and must not appear in logs or generated files.

Before handing off a code change, run the relevant tests plus:

```bash
.venv/bin/pytest
.venv/bin/ruff check .
.venv/bin/mypy src
```
