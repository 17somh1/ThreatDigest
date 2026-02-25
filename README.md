# ThreatDigest
A portfolio-grade daily threat digest with a spicy-but-educational voice. It ingests free RSS/Atom feeds, filters and ranks items, summarizes each with OpenAI into a strict JSON schema, and publishes a static site via GitHub Pages.

## Architecture

```
RSS/Atom feeds -> filter + dedupe + rank -> OpenAI JSON summaries
                         |                       |
                         +----> themes (OpenAI) -+

Rendered HTML -> docs/index.html + docs/archive/YYYY-MM-DD.html
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
  - `MAX_ITEMS` (optional, default `15`)
  - `RECENT_HOURS` (optional, default `48`)
  - `TONE_MODE` (optional, `spicy` or `clean`, default `spicy`)

## Cost controls

- Only recent items (last 24-48 hours) are considered.
- Dedupes by canonical URL and normalized title hash.
- Caps the number of items summarized per run (`MAX_ITEMS`).

## Methodology

The pipeline keeps only relevant items using keyword + source filters, ranks them deterministically, and summarizes each with a strict JSON schema. Any jargon used must be defined for beginners. If source content is thin, the model is instructed to set confidence to LOW and explain uncertainty.

## GitHub Actions

The workflow in `.github/workflows/digest.yml` runs daily on a cron schedule, generates the digest, and deploys `docs/` to GitHub Pages.
