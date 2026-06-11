from __future__ import annotations

from websec_audit.checks.csrf import check_csrf
from websec_audit.checks.headers import check_security_headers
from websec_audit.checks.sqli import SqliScanner
from websec_audit.checks.xss import XssScanner
from websec_audit.crawler import Crawler
from websec_audit.http_client import HttpClient, RequestsHttpClient
from websec_audit.models import Finding, ScanConfig, ScanReport, Severity


class SecurityAuditor:
    def __init__(self, config: ScanConfig, client: HttpClient | None = None) -> None:
        self._config = config
        self._client = client or RequestsHttpClient(
            timeout=config.timeout,
            user_agent=config.user_agent,
            verify_tls=config.verify_tls,
        )

    def run(self) -> ScanReport:
        report = ScanReport(target_url=self._config.target_url)
        crawler = Crawler(config=self._config, client=self._client)
        crawl_result = crawler.crawl()
        report.pages.extend(crawl_result.pages)

        for url, error in crawl_result.errors.items():
            is_crawl_limitation = "anti-bot or browser challenge" in error
            report.findings.append(
                Finding(
                    check_id="crawler.limitation" if is_crawl_limitation else "crawler.fetch-error",
                    title=(
                        "Crawl was limited by a browser challenge"
                        if is_crawl_limitation
                        else "Page could not be fetched"
                    ),
                    severity=Severity.INFO,
                    url=url,
                    description=(
                        "The crawler reached a bot-protection or browser challenge page instead "
                        "of the real application."
                        if is_crawl_limitation
                        else "The crawler could not retrieve this URL."
                    ),
                    evidence=error,
                    recommendation=(
                        "Run the audit against an authorized test/staging endpoint, allowlist "
                        "the scanner, or provide a target that does not require interactive "
                        "anti-bot validation."
                        if is_crawl_limitation
                        else "Verify that the URL is reachable and allowed by the target."
                    ),
                )
            )

        xss_scanner = XssScanner(self._client)
        sqli_scanner = SqliScanner(self._client)

        for page in report.pages:
            report.findings.extend(check_security_headers(page))
            report.findings.extend(check_csrf(page))

            if not self._config.active_checks:
                continue

            for form in page.forms:
                report.findings.extend(xss_scanner.scan(form))
                report.findings.extend(sqli_scanner.scan(form))

        report.findings = _deduplicate(report.findings)
        report.finish()
        return report


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.check_id, finding.url, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
