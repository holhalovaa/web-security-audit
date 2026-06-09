from websec_audit.checks.csrf import check_csrf
from websec_audit.checks.headers import check_security_headers
from websec_audit.models import Form, FormField, Page


def test_missing_security_headers_are_reported() -> None:
    page = Page(
        url="https://example.test/",
        status_code=200,
        headers={"Server": "demo"},
    )

    findings = check_security_headers(page)

    assert {finding.check_id for finding in findings} >= {
        "headers.content-security-policy",
        "headers.strict-transport-security",
        "headers.x-frame-options",
    }


def test_configured_security_headers_do_not_create_findings() -> None:
    page = Page(
        url="https://example.test/",
        status_code=200,
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
        },
    )

    assert check_security_headers(page) == []


def test_state_changing_form_without_csrf_token_is_reported() -> None:
    page = Page(
        url="https://example.test/login",
        status_code=200,
        headers={},
        forms=(
            Form(
                page_url="https://example.test/login",
                action="https://example.test/login",
                method="post",
                fields=(FormField(name="email"), FormField(name="password")),
            ),
        ),
    )

    findings = check_csrf(page)

    assert len(findings) == 1
    assert findings[0].check_id == "csrf.missing-token"


def test_form_with_csrf_token_is_accepted() -> None:
    page = Page(
        url="https://example.test/login",
        status_code=200,
        headers={},
        forms=(
            Form(
                page_url="https://example.test/login",
                action="https://example.test/login",
                method="post",
                fields=(FormField(name="csrf_token"), FormField(name="email")),
            ),
        ),
    )

    assert check_csrf(page) == []
