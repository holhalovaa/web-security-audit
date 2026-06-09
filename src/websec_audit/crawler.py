from __future__ import annotations

from collections import deque
from dataclasses import dataclass

import requests

from websec_audit.http_client import HttpClient
from websec_audit.models import Page, ScanConfig
from websec_audit.parser import extract_forms, extract_links, extract_title
from websec_audit.url_utils import is_in_scope, normalize_url


@dataclass(frozen=True)
class CrawlResult:
    pages: list[Page]
    errors: dict[str, str]


class Crawler:
    def __init__(self, config: ScanConfig, client: HttpClient) -> None:
        self._config = config
        self._client = client

    def crawl(self) -> CrawlResult:
        start_url = normalize_url(self._config.target_url, self._config.target_url)
        if start_url is None:
            raise ValueError("Target URL must be an absolute http(s) URL")

        queue: deque[tuple[str, int]] = deque([(start_url, 0)])
        visited: set[str] = set()
        pages: list[Page] = []
        errors: dict[str, str] = {}

        while queue and len(pages) < self._config.max_pages:
            url, depth = queue.popleft()
            if url in visited:
                continue
            visited.add(url)

            try:
                response = self._client.get(url)
            except requests.RequestException as exc:
                errors[url] = str(exc)
                continue

            content_type = response.headers.get("content-type", "")
            is_html = "html" in content_type.lower() or response.text.lstrip().startswith("<")
            links = extract_links(response.url, response.text) if is_html else ()
            forms = extract_forms(response.url, response.text) if is_html else ()

            page = Page(
                url=response.url,
                status_code=response.status_code,
                headers=response.headers,
                title=extract_title(response.text) if is_html else "",
                links=links,
                forms=forms,
            )
            pages.append(page)

            if depth >= self._config.max_depth:
                continue

            for link in links:
                if link not in visited and is_in_scope(
                    start_url,
                    link,
                    include_subdomains=self._config.include_subdomains,
                ):
                    queue.append((link, depth + 1))

        return CrawlResult(pages=pages, errors=errors)
