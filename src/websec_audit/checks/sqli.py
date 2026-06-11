from __future__ import annotations

import re

import requests

from websec_audit.checks.payloads import build_form_payload, curl_command, injectable_field_names
from websec_audit.http_client import HttpClient
from websec_audit.models import Finding, Form, Severity

SQLI_PAYLOADS = ("'", "\"", "' OR '1'='1", "1 OR 1=1")
SQL_ERROR_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"sql syntax",
        r"mysql_fetch",
        r"you have an error in your sql",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"sqlite error",
        r"postgresql.*error",
        r"ora-\d{5}",
    )
)


class SqliScanner:
    def __init__(self, client: HttpClient) -> None:
        self._client = client

    def scan(self, form: Form) -> list[Finding]:
        baseline = self._baseline(form)
        baseline_error = _match_sql_error(baseline.text) if baseline is not None else None
        baseline_status = baseline.status_code if baseline is not None else None

        for field_name in injectable_field_names(form):
            for payload in SQLI_PAYLOADS:
                data = build_form_payload(form, payload, target_field=field_name)
                if not data:
                    continue
                try:
                    response = self._client.submit(form.method, form.action, data)
                except requests.RequestException:
                    continue

                matched = _match_sql_error(response.text)
                if matched is None or matched == baseline_error:
                    continue

                status_note = (
                    f"; status changed from {baseline_status} to {response.status_code}"
                    if baseline_status is not None and baseline_status != response.status_code
                    else ""
                )
                return [
                    Finding(
                        check_id="sqli.error-based",
                        title="Possible SQL injection",
                        severity=Severity.HIGH,
                        url=response.url,
                        description=(
                            "The application returned a database error after receiving an SQL "
                            "injection probe."
                        ),
                        evidence=(
                            f"Field {field_name!r} with payload {payload!r} triggered "
                            f"pattern {matched!r}{status_note}."
                        ),
                        recommendation=(
                            "Use parameterized queries, avoid string concatenation in SQL, and "
                            "hide database errors from users."
                        ),
                        cwe="CWE-89",
                        owasp="A03:2021 Injection",
                        poc=curl_command(form.method, form.action, data),
                    )
                ]
        return []

    def _baseline(self, form: Form):
        data = {field.name: field.value for field in form.fields if field.name}
        if not data:
            return None
        try:
            return self._client.submit(form.method, form.action, data)
        except requests.RequestException:
            return None


def _match_sql_error(text: str) -> str | None:
    for pattern in SQL_ERROR_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None
