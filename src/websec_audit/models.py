from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class FormField:
    name: str
    field_type: str = "text"
    value: str = ""


@dataclass(frozen=True)
class Form:
    page_url: str
    action: str
    method: str
    fields: tuple[FormField, ...] = ()

    @property
    def field_names(self) -> set[str]:
        return {field.name for field in self.fields if field.name}


@dataclass(frozen=True)
class Page:
    url: str
    status_code: int
    headers: dict[str, str]
    title: str = ""
    links: tuple[str, ...] = ()
    forms: tuple[Form, ...] = ()


@dataclass(frozen=True)
class Finding:
    check_id: str
    title: str
    severity: Severity
    url: str
    description: str
    evidence: str
    recommendation: str
    cwe: str | None = None
    owasp: str | None = None
    poc: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "url": self.url,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "poc": self.poc,
        }


@dataclass(frozen=True)
class ScanConfig:
    target_url: str
    max_depth: int = 2
    max_pages: int = 50
    timeout: float = 10.0
    user_agent: str = "web-security-audit/0.1"
    include_subdomains: bool = False
    active_checks: bool = True
    verify_tls: bool = True
    crawl_engine: str = "auto"


@dataclass
class ScanReport:
    target_url: str
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    pages: list[Page] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def finish(self) -> None:
        self.finished_at = datetime.now(UTC)

    @property
    def duration_seconds(self) -> float:
        end = self.finished_at or datetime.now(UTC)
        return round((end - self.started_at).total_seconds(), 3)

    @property
    def summary_by_severity(self) -> dict[str, int]:
        summary = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            summary[finding.severity.value] += 1
        return summary

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
            "summary_by_severity": self.summary_by_severity,
            "pages": [
                {
                    "url": page.url,
                    "status_code": page.status_code,
                    "title": page.title,
                    "links": list(page.links),
                    "forms": [
                        {
                            "page_url": form.page_url,
                            "action": form.action,
                            "method": form.method,
                            "fields": [
                                {
                                    "name": field.name,
                                    "field_type": field.field_type,
                                    "value": field.value,
                                }
                                for field in form.fields
                            ],
                        }
                        for form in page.forms
                    ],
                }
                for page in self.pages
            ],
            "findings": [finding.to_dict() for finding in self.findings],
        }
