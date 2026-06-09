from __future__ import annotations

from dataclasses import dataclass

from websec_audit.models import Finding, Page, Severity


@dataclass(frozen=True)
class HeaderRule:
    name: str
    title: str
    severity: Severity
    recommendation: str
    cwe: str | None = None


HEADER_RULES = (
    HeaderRule(
        name="content-security-policy",
        title="Missing Content Security Policy",
        severity=Severity.HIGH,
        recommendation="Configure a strict Content-Security-Policy header.",
        cwe="CWE-693",
    ),
    HeaderRule(
        name="strict-transport-security",
        title="Missing HTTP Strict Transport Security",
        severity=Severity.MEDIUM,
        recommendation="Add Strict-Transport-Security with an appropriate max-age value.",
        cwe="CWE-319",
    ),
    HeaderRule(
        name="x-frame-options",
        title="Missing clickjacking protection",
        severity=Severity.MEDIUM,
        recommendation="Set X-Frame-Options or frame-ancestors in Content-Security-Policy.",
        cwe="CWE-1021",
    ),
    HeaderRule(
        name="x-content-type-options",
        title="Missing MIME sniffing protection",
        severity=Severity.LOW,
        recommendation="Set X-Content-Type-Options: nosniff.",
        cwe="CWE-16",
    ),
    HeaderRule(
        name="referrer-policy",
        title="Missing Referrer Policy",
        severity=Severity.LOW,
        recommendation="Set a Referrer-Policy such as strict-origin-when-cross-origin.",
    ),
    HeaderRule(
        name="permissions-policy",
        title="Missing Permissions Policy",
        severity=Severity.LOW,
        recommendation="Set Permissions-Policy to disable unused browser capabilities.",
    ),
)


def check_security_headers(page: Page) -> list[Finding]:
    normalized_headers = {key.lower(): value for key, value in page.headers.items()}
    findings: list[Finding] = []

    for rule in HEADER_RULES:
        if rule.name in normalized_headers:
            continue
        findings.append(
            Finding(
                check_id=f"headers.{rule.name}",
                title=rule.title,
                severity=rule.severity,
                url=page.url,
                description=f"The response does not include the {rule.name} header.",
                evidence=f"Observed headers: {', '.join(sorted(normalized_headers)) or 'none'}",
                recommendation=rule.recommendation,
                cwe=rule.cwe,
                owasp="A05:2021 Security Misconfiguration",
            )
        )

    hsts = normalized_headers.get("strict-transport-security")
    if page.url.startswith("https://") and hsts and "max-age=0" in hsts.replace(" ", "").lower():
        findings.append(
            Finding(
                check_id="headers.hsts-disabled",
                title="HSTS is explicitly disabled",
                severity=Severity.MEDIUM,
                url=page.url,
                description="The Strict-Transport-Security header disables HSTS with max-age=0.",
                evidence=f"Strict-Transport-Security: {hsts}",
                recommendation="Use a positive max-age value and include subdomains when appropriate.",
                cwe="CWE-319",
                owasp="A05:2021 Security Misconfiguration",
            )
        )

    return findings
