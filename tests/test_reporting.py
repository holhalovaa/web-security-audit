import websec_audit.reporting.html_report as html_report
from websec_audit.models import Finding, ScanReport, Severity


def test_render_report_without_findings() -> None:
    report = ScanReport(target_url="https://example.test/")
    report.finish()

    html = html_report.render_html_report(report)

    assert "Проблемы безопасности не обнаружены." in html
    assert "https://example.test/" in html


def test_write_html_report_creates_parent_directory(tmp_path) -> None:
    report = ScanReport(target_url="https://example.test/")
    output_path = tmp_path / "reports" / "report.html"

    html_report.write_html_report(report, output_path)

    assert output_path.exists()
    assert "Отчет аудита безопасности веб-приложения" in output_path.read_text(
        encoding="utf-8"
    )


def test_write_pdf_report_uses_playwright(monkeypatch, tmp_path) -> None:
    output_path = tmp_path / "reports" / "report.pdf"
    calls: list[tuple[str, object]] = []

    class PageStub:
        def set_content(self, html: str, wait_until: str) -> None:
            calls.append(("set_content", wait_until))
            assert "Отчет аудита безопасности веб-приложения" in html

        def pdf(self, **kwargs) -> None:
            calls.append(("pdf", kwargs))

    class BrowserStub:
        def new_page(self) -> PageStub:
            calls.append(("new_page", None))
            return PageStub()

        def close(self) -> None:
            calls.append(("close", None))

    class ChromiumStub:
        def launch(self) -> BrowserStub:
            calls.append(("launch", None))
            return BrowserStub()

    class PlaywrightStub:
        chromium = ChromiumStub()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback) -> None:
            calls.append(("exit", exc_type))

    monkeypatch.setattr(html_report, "sync_playwright", PlaywrightStub)

    report = ScanReport(target_url="https://example.test/")
    html_report.write_pdf_report(report, output_path)

    assert calls[0] == ("launch", None)
    assert ("set_content", "networkidle") in calls
    assert (
        "pdf",
        {"path": str(output_path), "format": "A4", "print_background": True},
    ) in calls
    assert ("close", None) in calls
    assert output_path.parent.exists()


def test_report_escapes_poc_and_references() -> None:
    report = ScanReport(target_url="https://example.test/")
    report.findings.append(
        Finding(
            check_id="xss.reflected",
            title="<script>",
            severity=Severity.HIGH,
            url="https://example.test/?x=<script>",
            description="reflected",
            evidence="<script>alert(1)</script>",
            recommendation="encode",
            cwe="CWE-79",
            owasp="A03:2021 Injection",
            poc="curl 'https://example.test/?x=<script>'",
        )
    )

    html = html_report.render_html_report(report)

    assert "&lt;script&gt;" in html
    assert "CWE-79 A03:2021 Injection" in html
    assert "Proof of Concept" in html
    assert "Доказательство" in html
