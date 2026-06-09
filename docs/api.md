# API Documentation

The project exposes a command-line interface and a small Python API for tests,
automation, and future integrations.

## CLI

```bash
websec-audit TARGET [options]
```

Required argument:

- `TARGET`: absolute `http` or `https` base URL.

Common options:

- `--max-depth`: maximum crawl depth. Default: `2`.
- `--max-pages`: maximum number of pages. Default: `50`.
- `--timeout`: HTTP timeout in seconds. Default: `10`.
- `--include-subdomains`: include target subdomains in crawl scope.
- `--no-active-checks`: disable XSS and SQLi form submissions.
- `--no-verify-tls`: disable TLS verification for lab targets.
- `--html-output`: HTML report path. Default: `reports/report.html`.
- `--pdf-output`: optional PDF report path.
- `--json-output`: optional JSON report path.

## Python API

```python
from websec_audit import ScanConfig
from websec_audit.scanner import SecurityAuditor

config = ScanConfig(
    target_url="https://example.com",
    max_depth=2,
    max_pages=30,
    active_checks=False,
)

report = SecurityAuditor(config).run()
```

Important models:

- `ScanConfig`: scan limits, target URL, active/passive mode and TLS settings.
- `ScanReport`: crawled pages, findings, duration and severity summary.
- `Page`: normalized URL, status, headers, links and discovered forms.
- `Form`: action, method and parsed fields.
- `Finding`: check identifier, severity, evidence, recommendation and optional PoC.

## Exit Behavior

The CLI exits with `0` after a completed scan, even when findings are detected.
Findings are security results, not process failures. Invalid input exits through
`argparse` with a non-zero code.
