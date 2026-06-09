from collections.abc import Mapping

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


def test_html_report_contains_summary_and_findings() -> None:
    report = SecurityAuditor(
        ScanConfig(target_url="https://example.test/", max_depth=0, active_checks=False),
        client=AuditClient(),
    ).run()

    html = render_html_report(report)

    assert "Web Security Audit Report" in html
    assert "Audit me" in html
    assert "Missing Content Security Policy" in html
