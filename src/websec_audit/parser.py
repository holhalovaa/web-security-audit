from __future__ import annotations

from bs4 import BeautifulSoup

from websec_audit.models import Form, FormField
from websec_audit.url_utils import normalize_url


def extract_title(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    title = soup.find("title")
    if title is None:
        return ""
    return " ".join(title.get_text(" ", strip=True).split())


def extract_links(page_url: str, html: str) -> tuple[str, ...]:
    soup = BeautifulSoup(html, "html.parser")
    links: set[str] = set()
    for anchor in soup.find_all("a", href=True):
        normalized = normalize_url(page_url, anchor["href"])
        if normalized:
            links.add(normalized)
    return tuple(sorted(links))


def extract_forms(page_url: str, html: str) -> tuple[Form, ...]:
    soup = BeautifulSoup(html, "html.parser")
    forms: list[Form] = []

    for raw_form in soup.find_all("form"):
        method = (raw_form.get("method") or "get").strip().lower()
        action = normalize_url(page_url, raw_form.get("action") or page_url)
        if action is None:
            continue

        fields: list[FormField] = []
        for element in raw_form.find_all(["input", "textarea", "select"]):
            name = (element.get("name") or "").strip()
            if not name:
                continue
            field_type = (element.get("type") or _default_field_type(element.name)).strip().lower()
            value = _extract_value(element, field_type)
            fields.append(FormField(name=name, field_type=field_type, value=value))

        forms.append(
            Form(
                page_url=page_url,
                action=action,
                method=method if method in {"get", "post", "put", "patch", "delete"} else "get",
                fields=tuple(fields),
            )
        )

    return tuple(forms)


def _extract_value(element: object, field_type: str) -> str:
    if field_type == "select":
        selected = element.find("option", selected=True)
        option = selected or element.find("option")
        return (option.get("value") if option else "") or ""
    if field_type == "textarea":
        return element.get_text("", strip=False)
    return (element.get("value") or "").strip()


def _default_field_type(tag_name: str | None) -> str:
    if tag_name == "textarea":
        return "textarea"
    if tag_name == "select":
        return "select"
    return "text"
