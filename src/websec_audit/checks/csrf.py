from __future__ import annotations

from websec_audit.models import Finding, Form, Page, Severity

STATE_CHANGING_METHODS = {"post", "put", "patch", "delete"}
TOKEN_MARKERS = ("csrf", "_csrf", "xsrf", "token", "authenticity")


def check_csrf(page: Page) -> list[Finding]:
    findings: list[Finding] = []
    for form in page.forms:
        if not _is_state_changing(form) or _has_csrf_token(form):
            continue
        findings.append(
            Finding(
                check_id="csrf.missing-token",
                title="State-changing form without CSRF token",
                severity=Severity.MEDIUM,
                url=form.page_url,
                description=(
                    "A form that can change server-side state does not include a recognizable "
                    "anti-CSRF token field."
                ),
                evidence=f"{form.method.upper()} {form.action}; fields: {sorted(form.field_names)}",
                recommendation=(
                    "Add a per-request CSRF token and validate it server-side. Also use SameSite "
                    "cookies where possible."
                ),
                cwe="CWE-352",
                owasp="A01:2021 Broken Access Control",
            )
        )
    return findings


def _is_state_changing(form: Form) -> bool:
    return form.method.lower() in STATE_CHANGING_METHODS


def _has_csrf_token(form: Form) -> bool:
    names = {name.lower() for name in form.field_names}
    return any(marker in name for name in names for marker in TOKEN_MARKERS)
