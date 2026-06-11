from __future__ import annotations

import requests

from websec_audit.checks.payloads import build_form_payload, curl_command, injectable_field_names
from websec_audit.http_client import HttpClient
from websec_audit.models import Finding, Form, Severity

XSS_PAYLOAD = '<script>alert("websec-audit")</script>'


class XssScanner:
    def __init__(self, client: HttpClient) -> None:
        self._client = client

    def scan(self, form: Form) -> list[Finding]:
        findings: list[Finding] = []

        for field_name in injectable_field_names(form):
            payload = XSS_PAYLOAD
            data = build_form_payload(form, payload, target_field=field_name)
            if not data:
                continue

            try:
                response = self._client.submit(form.method, form.action, data)
            except requests.RequestException:
                continue

            if payload not in response.text:
                continue

            findings.append(
                Finding(
                    check_id="xss.reflected",
                    title="Reflected XSS payload detected",
                    severity=Severity.HIGH,
                    url=response.url,
                    description=(
                        "The application reflected an executable script payload in the HTTP "
                        "response."
                    ),
                    evidence=f"Field {field_name!r} reflected payload: {payload}",
                    recommendation=(
                        "Apply contextual output encoding, validate input, and enforce a strict "
                        "Content-Security-Policy."
                    ),
                    cwe="CWE-79",
                    owasp="A03:2021 Injection",
                    poc=curl_command(form.method, form.action, data),
                )
            )

        return findings
