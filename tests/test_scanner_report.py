from collections.abc import Mapping

import requests

from websec_audit.http_client import HttpResponse
from websec_audit.models import ScanConfig
from websec_audit.reporting.html_report import render_html_report
from websec_audit.scanner import SecurityAuditor


class AuditClient:
    def get(self, url: str) -> HttpResponse:
        return HttpResponse(
            url=url,
            status_code=200,
            headers={"content-type": "text/html"},
            text="""
            <html>
              <title>Audit me</title>
              <form method="post" action="/login">
                <input name="email" type="email">
              </form>
            </html>
            """,
        )

    def submit(self, method: str, url: str, data: Mapping[str, str]) -> HttpResponse:
        return HttpResponse(url=url, status_code=200, headers={}, text="<html>clean</html>")


class ErrorClient(AuditClient):
    def get(self, url: str) -> HttpResponse:
        raise requests.RequestException("timeout")


def test_security_auditor_runs_passive_checks() -> None:
    report = SecurityAuditor(
        ScanConfig(
            target_url="https://example.test/",
            max_depth=0,
            active_checks=False,
        ),
        client=AuditClient(),
    ).run()

    assert len(report.pages) == 1
    assert report.pages[0].title == "Audit me"
    assert {finding.check_id for finding in report.findings} >= {
        "headers.content-security-policy",
        "csrf.missing-token",
    }
    assert report.finished_at is not None


def test_security_auditor_reports_crawler_errors() -> None:
    report = SecurityAuditor(
        ScanConfig(target_url="https://example.test/", max_depth=0),
        client=ErrorClient(),
    ).run()

    assert report.pages == []
    assert len(report.findings) == 1
    assert report.findings[0].check_id == "crawler.fetch-error"


def test_security_auditor_skips_header_checks_for_json_pages() -> None:
    class JsonClient(AuditClient):
        def get(self, url: str) -> HttpResponse:
            return HttpResponse(
                url=url,
                status_code=200,
                headers={"content-type": "application/json"},
                text='{"ok": true}',
            )

    report = SecurityAuditor(
        ScanConfig(target_url="https://example.test/api", max_depth=0, active_checks=False),
        client=JsonClient(),
    ).run()

    assert report.pages[0].content_type == "application/json"
    assert report.findings == []


def test_security_auditor_reports_challenge_as_limitation_only() -> None:
    class ChallengeClient(AuditClient):
        def get(self, url: str) -> HttpResponse:
            return HttpResponse(
                url=url,
                status_code=498,
                headers={"content-type": "text/html"},
                text="<html><title>Почти готово...</title><body>antibot challenge</body></html>",
            )

    report = SecurityAuditor(
        ScanConfig(target_url="https://example.test/", max_depth=0, active_checks=False),
        client=ChallengeClient(),
    ).run()

    assert [finding.check_id for finding in report.findings] == ["crawler.limitation"]


def test_security_auditor_deduplicates_active_findings() -> None:
    class VulnerableClient(AuditClient):
        def submit(self, method: str, url: str, data: Mapping[str, str]) -> HttpResponse:
            return HttpResponse(
                url=url,
                status_code=200,
                headers={},
                text='<script>alert("websec-audit")</script>',
            )

    report = SecurityAuditor(
        ScanConfig(target_url="https://example.test/", max_depth=0, active_checks=True),
        client=VulnerableClient(),
    ).run()

    finding_ids = [finding.check_id for finding in report.findings]

    assert finding_ids.count("xss.reflected") == 1


def test_html_report_contains_summary_and_findings() -> None:
    report = SecurityAuditor(
        ScanConfig(target_url="https://example.test/", max_depth=0, active_checks=False),
        client=AuditClient(),
    ).run()

    html = render_html_report(report)

    assert "Отчет аудита безопасности веб-приложения" in html
    assert "Audit me" in html
    assert "Missing Content Security Policy" in html
