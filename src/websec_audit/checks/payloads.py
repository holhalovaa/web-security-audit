from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import urlencode

from websec_audit.models import Form

INJECTABLE_FIELD_TYPES = {
    "email",
    "number",
    "password",
    "search",
    "tel",
    "text",
    "textarea",
    "url",
}


def build_form_payload(form: Form, payload: str, target_field: str | None = None) -> dict[str, str]:
    data: dict[str, str] = {}
    injected = False
    for field in form.fields:
        should_inject = (
            field.name == target_field
            if target_field is not None
            else field.field_type in INJECTABLE_FIELD_TYPES
        )
        if should_inject:
            data[field.name] = payload
            injected = True
        else:
            data[field.name] = field.value
    if not injected and form.fields:
        first = form.fields[0]
        data[first.name] = payload
    return data


def injectable_field_names(form: Form) -> tuple[str, ...]:
    names = tuple(
        field.name
        for field in form.fields
        if field.name and field.field_type in INJECTABLE_FIELD_TYPES
    )
    if names:
        return names
    return tuple(field.name for field in form.fields if field.name)[:1]


def curl_command(method: str, url: str, data: Mapping[str, str]) -> str:
    quoted_url = _single_quote(url)
    normalized_method = method.upper()
    if normalized_method == "GET":
        separator = "&" if "?" in url else "?"
        query_url = f"{url}{separator}{urlencode(data)}" if data else url
        return f"curl -i {_single_quote(query_url)}"
    chunks = ["curl", "-i", "-X", normalized_method, quoted_url]
    for key, value in data.items():
        chunks.extend(["-d", _single_quote(f"{key}={value}")])
    return " ".join(chunks)


def _single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"
