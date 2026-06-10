from collections.abc import Mapping

import requests

from websec_audit.checks.payloads import build_form_payload, curl_command
from websec_audit.checks.sqli import SqliScanner
from websec_audit.checks.xss import XSS_PAYLOAD, XssScanner
from websec_audit.http_client import HttpResponse
from websec_audit.models import Form, FormField


class EchoClient:
    def __init__(self, body: str) -> None:
        self.body = body
        self.submitted: list[dict[str, str]] = []

    def get(self, url: str) -> HttpResponse:
        raise AssertionError("active scanner must not crawl")

    def submit(self, method: str, url: str, data: Mapping[str, str]) -> HttpResponse:
        self.submitted.append(dict(data))
        return HttpResponse(url=url, status_code=200, headers={}, text=self.body)


class FailingClient(EchoClient):
    def submit(self, method: str, url: str, data: Mapping[str, str]) -> HttpResponse:
        raise requests.RequestException("network error")


def test_xss_scanner_reports_reflected_payload() -> None:
    form = Form(
        page_url="https://example.test/search",
        action="https://example.test/search",
        method="get",
        fields=(FormField(name="q"),),
    )
    scanner = XssScanner(EchoClient(f"<html>{XSS_PAYLOAD}</html>"))

    findings = scanner.scan(form)

    assert len(findings) == 1
    assert findings[0].check_id == "xss.reflected"
    assert "curl -i" in findings[0].poc


def test_xss_scanner_ignores_clean_response_and_network_errors() -> None:
    form = Form(
        page_url="https://example.test/search",
        action="https://example.test/search",
        method="get",
        fields=(FormField(name="q"),),
    )

    assert XssScanner(EchoClient("<html>clean</html>")).scan(form) == []
    assert XssScanner(FailingClient("")).scan(form) == []
    assert XssScanner(EchoClient("")).scan(
        Form(page_url=form.page_url, action=form.action, method=form.method)
    ) == []


def test_sqli_scanner_reports_database_error_pattern() -> None:
    form = Form(
        page_url="https://example.test/login",
        action="https://example.test/login",
        method="post",
        fields=(FormField(name="username"), FormField(name="password")),
    )
    scanner = SqliScanner(EchoClient("You have an error in your SQL syntax near quote"))

    findings = scanner.scan(form)

    assert len(findings) == 1
    assert findings[0].check_id == "sqli.error-based"
    assert findings[0].poc is not None


def test_sqli_scanner_ignores_clean_response_empty_forms_and_network_errors() -> None:
    form = Form(
        page_url="https://example.test/login",
        action="https://example.test/login",
        method="post",
        fields=(FormField(name="username"),),
    )

    assert SqliScanner(EchoClient("<html>clean</html>")).scan(form) == []
    assert SqliScanner(FailingClient("")).scan(form) == []
    assert SqliScanner(EchoClient("")).scan(
        Form(page_url=form.page_url, action=form.action, method=form.method)
    ) == []


def test_payload_builder_falls_back_to_first_non_injectable_field() -> None:
    form = Form(
        page_url="https://example.test/delete",
        action="https://example.test/delete",
        method="post",
        fields=(FormField(name="csrf", field_type="hidden", value="token"),),
    )

    assert build_form_payload(form, "payload") == {"csrf": "payload"}
    assert "csrf=payload" in curl_command("post", form.action, {"csrf": "payload"})
