from pathlib import Path

import pytest

from websec_audit import web
from websec_audit.models import Finding, Page, ScanReport, Severity


class FakeAuditor:
    last_config = None

    def __init__(self, config) -> None:
        FakeAuditor.last_config = config

    def run(self) -> ScanReport:
        report = ScanReport(target_url=FakeAuditor.last_config.target_url)
        report.pages.append(
            Page(
                url=FakeAuditor.last_config.target_url,
                status_code=200,
                headers={},
                title="Demo",
            )
        )
        report.findings.append(
            Finding(
                check_id="headers.missing",
                title="Missing header",
                severity=Severity.LOW,
                url=FakeAuditor.last_config.target_url,
                description="Header is absent.",
                evidence="Content-Security-Policy",
                recommendation="Add the header.",
                poc="curl -I https://example.test",
            )
        )
        report.finish()
        return report


def test_web_app_runs_scan_and_writes_reports(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(web, "SecurityAuditor", FakeAuditor)

    pdf_calls: list[Path] = []

    def fake_write_pdf(report: ScanReport, output_path: Path) -> None:
        pdf_calls.append(output_path)
        output_path.write_text("pdf", encoding="utf-8")

    monkeypatch.setattr(web, "write_pdf_report", fake_write_pdf)

    app = web.AuditWebApp(reports_dir=tmp_path)
    result = app.run_scan(
        {
            "target": ["https://example.test/"],
            "mode": ["active"],
            "max_depth": ["3"],
            "max_pages": ["12"],
            "timeout": ["4.5"],
            "crawl_engine": ["playwright"],
            "include_subdomains": ["on"],
            "no_verify_tls": ["on"],
            "pdf_report": ["on"],
        }
    )

    assert result.scan_id in app.results
    assert result.html_path.exists()
    assert result.json_path.exists()
    assert result.pdf_path is not None
    assert result.pdf_path.exists()
    assert pdf_calls == [result.pdf_path]
    assert FakeAuditor.last_config.active_checks is True
    assert FakeAuditor.last_config.include_subdomains is True
    assert FakeAuditor.last_config.verify_tls is False
    assert FakeAuditor.last_config.max_depth == 3
    assert FakeAuditor.last_config.max_pages == 12
    assert FakeAuditor.last_config.timeout == 4.5
    assert FakeAuditor.last_config.crawl_engine == "playwright"


def test_web_app_rejects_non_http_target(tmp_path) -> None:
    app = web.AuditWebApp(reports_dir=tmp_path)

    with pytest.raises(ValueError, match="URL"):
        app.run_scan({"target": ["javascript:alert(1)"]})


def test_render_result_contains_links_and_escapes_content(tmp_path) -> None:
    report = ScanReport(target_url="https://example.test/?q=<script>")
    report.pages.append(Page(url="https://example.test/", status_code=200, headers={}))
    report.findings.append(
        Finding(
            check_id="xss.reflected",
            title="<script>",
            severity=Severity.HIGH,
            url="https://example.test/?q=<script>",
            description="reflected",
            evidence="<script>alert(1)</script>",
            recommendation="Encode output.",
        )
    )
    report.finish()

    result = web.WebScanResult(
        scan_id="abc",
        report=report,
        html_path=Path("reports/web-abc/report.html"),
        json_path=Path("reports/web-abc/report.json"),
        pdf_path=Path("reports/web-abc/report.pdf"),
        active_checks=False,
    )

    html = web.render_result(result)

    assert "&lt;script&gt;" in html
    assert "/reports/web-abc/report.html" in html
    assert "/reports/web-abc/report.json" in html
    assert "/reports/web-abc/report.pdf" in html
    assert "пассивный" in html
    assert 'href="#severity-high"' in html
    assert 'class="back-top"' in html


def test_render_home_contains_loading_overlay() -> None:
    html = web.render_home()

    assert "Пожалуйста, подождите" in html
    assert "Примерное время" in html
    assert "data-loading-overlay" in html
