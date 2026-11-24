# apiapp-py

## Run locally

In PowerShell, from the repository root:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --require-hashes -r requirements.txt
Copy-Item .env.example .env
python uid2-api.py
```

The app loads `.env` for local development. Values already set in the process
environment take precedence, so deployment-provided secrets override local
settings. `.env` is ignored by Git; do not commit real credentials.

The example values are placeholders for local startup and health checks only.
They are not valid UID2 credentials, so token generation will not work until
you provide valid non-production `UID2_API_KEY` and `UID2_CLIENT_SECRET`
credentials. The local bearer token is `local-development-token`; send it as
an HTTP bearer authorization header when testing `POST /uid2/token`.

## GitHub security scans

`.github/workflows/security-scans.yml` runs Semgrep SAST and an OWASP ZAP
baseline DAST scan on pushes, pull requests, weekly, and on manual dispatch.
Both scanner images and GitHub Actions are pinned to immutable digests or
commits. Semgrep SARIF and the ZAP HTML report are uploaded as workflow
artifacts. ZAP warnings are retained in the report but do not fail the job by
themselves; confirmed ZAP failures still fail it.

The ZAP baseline scan is passive and unauthenticated; it is not a full
penetration test. The DAST job starts the API with placeholder credentials and
verifies that `/uid2/token` rejects unauthenticated requests. It does not call
the real UID2 service.