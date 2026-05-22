# CloudSpecter Defensive Assessment Workflow

This project is intentionally limited to local Docker, LocalStack, and authorized cloud accounts.

## What the toolkit does

- Validates whether a URL-fetch service can reach lab metadata-style paths.
- Detects whether the metadata service requires IMDSv2 tokens.
- Audits approved AWS or LocalStack accounts for common resources.
- Produces JSON and Markdown reports for comparison and remediation tracking.

## Local run

Install the scanner dependencies:

```powershell
python -m pip install -r scanner/requirements.txt
```

Run the comparison workflow against the local lab:

```powershell
.
scripts\run_defensive_assessment.ps1 `
  -VulnerableBaseUrl http://localhost:5000 `
  -ProtectedBaseUrl http://localhost:5000 `
  -ImdsVulnerable http://localhost:1338 `
  -ImdsProtected http://localhost:1338
```

If you have a protected IMDS instance or an alternate local mode, point `-ImdsProtected` at that endpoint.

## Docker run

Start the full lab stack:

```powershell
docker compose up --build
```

Scanner API endpoints:

- `GET /health`
- `GET /api/v1/providers`
- `POST /api/v1/metadata/assess`
- `POST /api/v1/metadata/compare`
- `POST /api/v1/metadata/report`

Example assessment request:

```json
{
  "endpoint": "http://localhost:1338",
  "provider": "aws",
  "label": "protected_mode",
  "token_ttl_seconds": 60
}
```

Example comparison request:

```json
{
  "vulnerable_endpoint": "http://localhost:1338",
  "protected_endpoint": "http://localhost:1338",
  "provider": "aws"
}
```

## Outputs

- JSON report: `artifacts/reports/cloudspecter-assessment.json`
- Markdown report: `artifacts/reports/cloudspecter-assessment.md`
- API report files: configured via `POST /api/v1/metadata/report`

## Notes

- The AWS audit stage is intended for LocalStack or explicitly authorized accounts.
- The toolkit does not include third-party exploitation automation or credential theft logic.