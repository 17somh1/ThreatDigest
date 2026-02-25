# ThreatDigest
A portfolio-grade, daily cyber threat digest built from free RSS/Atom feeds. It fetches recent items, filters and ranks them, summarizes each with OpenAI into a strict JSON schema, and renders a static site published via GitHub Pages.

## Architecture

```
RSS/Atom feeds -> filter + dedupe + rank -> OpenAI JSON summaries -> Jinja2 render -> docs/index.html + docs/archive/
```

## Local run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export OPENAI_API_KEY=...
python -m src.main
```

Outputs:
- `docs/index.html`
- `docs/archive/YYYY-MM-DD.html`

## Configuration

- `config/settings.yaml` contains the RSS feed list.
- Environment variables:
  - `OPENAI_API_KEY` (required)
  - `OPENAI_MODEL` (optional, default `gpt-4o-mini`)
  - `MAX_ITEMS_PER_RUN` (optional, default `15`)
  - `RECENT_HOURS` (optional, default `48`)

## Methodology

The pipeline filters to recent items, deduplicates by canonical URL and normalized title hash, and keeps at most 15 items per run. It boosts items containing CVE identifiers, zero-day indicators, ransomware/exploit keywords, and authoritative sources like CISA/NCSC. Risk and confidence are assigned by the model with a strict JSON schema to keep output stable across runs.

## GitHub Actions

The workflow in `.github/workflows/digest.yml` runs daily on a cron schedule, generates the digest, and commits updated `docs/` and `state.json` back to the repo. GitHub Pages should be configured to serve from the `docs/` folder.
