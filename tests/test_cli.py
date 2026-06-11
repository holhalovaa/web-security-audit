import json
from pathlib import Path

import pytest

from websec_audit import cli
from websec_audit.models import Finding, Page, ScanReport, Severity


class FakeAuditor:
    last_config = None

    def __init__(self, config) -> None:
        FakeAuditor.last_config = config

    def run(self) -> ScanReport:
        report = ScanReport(target_url=FakeAuditor.last_config.target_url)
        report.pages.append(Page(url="https://example.test/", status_code=200, headers={}))
        report.findings.append(
            Finding(
                check_id="demo",
                title="Demo finding",
                severity=Severity.LOW,
                url="https://example.test/",
                description="demo",
                evidence="demo",
                recommendation="fix",
            )
        )
        report.finish()
        return report


def test_cli_main_writes_requested_outputs(monkeypatch, tmp_path, capsys) -> None:
    html_path = tmp_path / "report.html"
    pdf_path = tmp_path / "report.pdf"
    json_path = tmp_path / "nested" / "report.json"
    calls: list[tuple[str, Path]] = []

    def fake_write_html(report: ScanReport, output_path: Path) -> None:
        calls.append(("html", output_path))
        output_path.write_text("html", encoding="utf-8")

    def fake_write_pdf(report: ScanReport, output_path: Path) -> None:
        calls.append(("pdf", output_path))
        output_path.write_text("pdf", encoding="utf-8")

    monkeypatch.setattr(cli, "SecurityAuditor", FakeAuditor)
    monkeypatch.setattr(cli, "write_html_report", fake_write_html)
    monkeypatch.setattr(cli, "write_pdf_report", fake_write_pdf)

    exit_code = cli.main(
        [
            "https://example.test/",
            "--max-depth",
            "-1",
            "--max-pages",
            "0",
            "--timeout",
            "3.5",
            "--user-agent",
            "tests",
            "--include-subdomains",
            "--no-active-checks",
            "--no-verify-tls",
            "--crawl-engine",
            "playwright",
            "--html-output",
            str(html_path),
            "--pdf-output",
            str(pdf_path),
            "--json-output",
            str(json_path),
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Scan completed" in output
    assert calls == [("html", html_path), ("pdf", pdf_path)]
    assert html_path.read_text(encoding="utf-8") == "html"
    assert pdf_path.read_text(encoding="utf-8") == "pdf"
    assert json.loads(json_path.read_text(encoding="utf-8"))["summary_by_severity"]["low"] == 1
    assert FakeAuditor.last_config.max_depth == 0
    assert FakeAuditor.last_config.max_pages == 1
    assert FakeAuditor.last_config.timeout == 3.5
    assert FakeAuditor.last_config.user_agent == "tests"
    assert FakeAuditor.last_config.include_subdomains is True
    assert FakeAuditor.last_config.active_checks is False
    assert FakeAuditor.last_config.verify_tls is False
    assert FakeAuditor.last_config.crawl_engine == "playwright"


def test_cli_rejects_invalid_target() -> None:
    with pytest.raises(SystemExit):
        cli.main(["not-a-url"])
