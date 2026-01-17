# ThreatDigest
An AI threat intelligence newsletter daily digest.

## Local run (stubbed)

```bash
SKIP_ENV_CHECK=1 python -m src.main
```

To run with real secrets, export the required env vars:

- `FEEDLY_TOKEN`
- `OPENAI_API_KEY`
- `EMAIL_API_KEY`
- `TO_EMAIL`
- `FROM_EMAIL`
