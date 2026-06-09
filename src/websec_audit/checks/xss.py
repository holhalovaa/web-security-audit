from __future__ import annotations

import requests

from websec_audit.checks.payloads import build_form_payload, curl_command
from websec_audit.http_client import HttpClient
from websec_audit.models import Finding, Form, Severity

XSS_PAYLOAD = '<script>alert("websec-audit")</script>'


class XssScanner:
    def __init__(self, client: HttpClient) -> None:
        self._client = client

    def scan(self, form: Form) -> list[Finding]:
        data = build_form_payload(form, XSS_PAYLOAD)
        if not data:
            return []

        try:
            response = self._client.submit(form.method, form.action, data)
        except requests.RequestException:
            return []

        if XSS_PAYLOAD not in response.text:
            return []

        return [
            Finding(
                check_id="xss.reflected",
                title="Reflected XSS payload detected",
                severity=Severity.HIGH,
                url=response.url,
                description=(
                    "The application reflected an executable script payload in the HTTP response."
                ),
                evidence=f"Payload reflected: {XSS_PAYLOAD}",
                recommendation=(
                    "Apply contextual output encoding, validate input, and enforce a strict "
                    "Content-Security-Policy."
                ),
                cwe="CWE-79",
                owasp="A03:2021 Injection",
                poc=curl_command(form.method, form.action, data),
            )
        ]
