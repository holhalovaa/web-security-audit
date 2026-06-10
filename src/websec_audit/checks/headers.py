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
        if rule.name == "x-frame-options" and _has_csp_frame_ancestors(normalized_headers):
            continue
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

    findings.extend(_check_csp(page, normalized_headers.get("content-security-policy")))
    findings.extend(_check_hsts(page, normalized_headers.get("strict-transport-security")))
    findings.extend(
        _check_x_frame_options(page, normalized_headers, normalized_headers.get("x-frame-options"))
    )
    findings.extend(
        _check_x_content_type_options(page, normalized_headers.get("x-content-type-options"))
    )
    findings.extend(_check_referrer_policy(page, normalized_headers.get("referrer-policy")))

    return findings


def _check_csp(page: Page, csp: str | None) -> list[Finding]:
    if not csp:
        return []

    normalized = csp.lower()
    unsafe_markers = ("'unsafe-inline'", "'unsafe-eval'", "default-src *", "script-src *")
    if not any(marker in normalized for marker in unsafe_markers):
        return []

    return [
        Finding(
            check_id="headers.content-security-policy-weak",
            title="Weak Content Security Policy",
            severity=Severity.MEDIUM,
            url=page.url,
            description="The Content-Security-Policy header allows unsafe script execution.",
            evidence=f"Content-Security-Policy: {csp}",
            recommendation=(
                "Avoid unsafe-inline, unsafe-eval and wildcard script sources. Prefer nonces, "
                "hashes and a tight allowlist."
            ),
            cwe="CWE-693",
            owasp="A05:2021 Security Misconfiguration",
        )
    ]


def _check_hsts(page: Page, hsts: str | None) -> list[Finding]:
    if not page.url.startswith("https://") or not hsts:
        return []

    compact = hsts.replace(" ", "").lower()
    if "max-age=0" in compact:
        return [
            Finding(
                check_id="headers.hsts-disabled",
                title="HSTS is explicitly disabled",
                severity=Severity.MEDIUM,
                url=page.url,
                description="The Strict-Transport-Security header disables HSTS with max-age=0.",
                evidence=f"Strict-Transport-Security: {hsts}",
                recommendation=(
                    "Use a positive max-age value and include subdomains when appropriate."
                ),
                cwe="CWE-319",
                owasp="A05:2021 Security Misconfiguration",
            )
        ]

    max_age = _extract_hsts_max_age(compact)
    if max_age is not None and max_age < 15_552_000:
        return [
            Finding(
                check_id="headers.hsts-short-max-age",
                title="HSTS max-age is too short",
                severity=Severity.LOW,
                url=page.url,
                description="The HSTS policy expires sooner than the recommended six months.",
                evidence=f"Strict-Transport-Security: {hsts}",
                recommendation="Use max-age of at least 15552000 seconds for production HTTPS.",
                cwe="CWE-319",
                owasp="A05:2021 Security Misconfiguration",
            )
        ]

    return []


def _check_x_frame_options(
    page: Page,
    headers: dict[str, str],
    x_frame_options: str | None,
) -> list[Finding]:
    if not x_frame_options or _has_csp_frame_ancestors(headers):
        return []

    normalized = x_frame_options.strip().lower()
    if normalized in {"deny", "sameorigin"}:
        return []

    return [
        Finding(
            check_id="headers.x-frame-options-invalid",
            title="Invalid clickjacking protection",
            severity=Severity.MEDIUM,
            url=page.url,
            description="The X-Frame-Options header value is not enforced by modern browsers.",
            evidence=f"X-Frame-Options: {x_frame_options}",
            recommendation="Use X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.",
            cwe="CWE-1021",
            owasp="A05:2021 Security Misconfiguration",
        )
    ]


def _has_csp_frame_ancestors(headers: dict[str, str]) -> bool:
    return "frame-ancestors" in headers.get("content-security-policy", "").lower()


def _check_x_content_type_options(page: Page, value: str | None) -> list[Finding]:
    if not value or value.strip().lower() == "nosniff":
        return []

    return [
        Finding(
            check_id="headers.x-content-type-options-invalid",
            title="Invalid MIME sniffing protection",
            severity=Severity.LOW,
            url=page.url,
            description="The X-Content-Type-Options header is present but does not enable nosniff.",
            evidence=f"X-Content-Type-Options: {value}",
            recommendation="Set X-Content-Type-Options: nosniff.",
            cwe="CWE-16",
            owasp="A05:2021 Security Misconfiguration",
        )
    ]


def _check_referrer_policy(page: Page, value: str | None) -> list[Finding]:
    unsafe_values = {"unsafe-url", "origin-when-cross-origin"}
    if not value or value.strip().lower() not in unsafe_values:
        return []

    return [
        Finding(
            check_id="headers.referrer-policy-unsafe",
            title="Unsafe Referrer Policy",
            severity=Severity.LOW,
            url=page.url,
            description="The Referrer-Policy header can leak full URLs or sensitive paths.",
            evidence=f"Referrer-Policy: {value}",
            recommendation="Use strict-origin-when-cross-origin, same-origin or no-referrer.",
            owasp="A05:2021 Security Misconfiguration",
        )
    ]


def _extract_hsts_max_age(compact_hsts: str) -> int | None:
    for directive in compact_hsts.split(";"):
        if not directive.startswith("max-age="):
            continue
        raw_value = directive.removeprefix("max-age=")
        if raw_value.isdigit():
            return int(raw_value)
    return None
