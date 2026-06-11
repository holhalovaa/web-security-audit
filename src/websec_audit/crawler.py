from __future__ import annotations

from collections import deque
from contextlib import suppress
from dataclasses import dataclass
from typing import Protocol

import requests

from websec_audit.http_client import HttpClient, HttpResponse
from websec_audit.models import Page, ScanConfig
from websec_audit.parser import extract_forms, extract_links, extract_title
from websec_audit.url_utils import is_in_scope, normalize_url


@dataclass(frozen=True)
class CrawlResult:
    pages: list[Page]
    errors: dict[str, str]


@dataclass(frozen=True)
class RenderedResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    html: str
    discovered_links: tuple[str, ...] = ()


class PageRenderer(Protocol):
    def render(self, url: str) -> RenderedResponse:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


class PlaywrightPageRenderer:
    def __init__(self, config: ScanConfig) -> None:
        from playwright.sync_api import TimeoutError, sync_playwright

        self._timeout_ms = int(config.timeout * 1000)
        self._timeout_error = TimeoutError
        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(headless=True)
        self._context = self._browser.new_context(
            user_agent=config.user_agent,
            ignore_https_errors=not config.verify_tls,
            viewport={"width": 1366, "height": 900},
        )
        self._context.route("**/*", self._route_request)

    def render(self, url: str) -> RenderedResponse:
        page = self._context.new_page()
        try:
            page.set_default_timeout(self._timeout_ms)
            response = page.goto(url, wait_until="domcontentloaded", timeout=self._timeout_ms)
            with suppress(self._timeout_error):
                page.wait_for_load_state("networkidle", timeout=min(self._timeout_ms, 5000))
            with suppress(self._timeout_error):
                page.wait_for_selector("body", timeout=min(self._timeout_ms, 5000))

            with suppress(Exception):
                self._expand_dynamic_content(page)
            discovered_links = self._extract_browser_links(page)

            return RenderedResponse(
                url=page.url,
                status_code=response.status if response else 0,
                headers=dict(response.headers) if response else {},
                html=page.content(),
                discovered_links=discovered_links,
            )
        finally:
            page.close()

    def close(self) -> None:
        self._context.close()
        self._browser.close()
        self._playwright.stop()

    @staticmethod
    def _route_request(route: object) -> None:
        request = route.request
        if request.resource_type in {"font", "image", "media"}:
            route.abort()
            return
        route.continue_()

    @staticmethod
    def _expand_dynamic_content(page: object) -> None:
        page.evaluate(
            """
            async () => {
              const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
              const maxScrolls = 6;
              let previousHeight = 0;
              for (let index = 0; index < maxScrolls; index += 1) {
                window.scrollTo(0, document.body.scrollHeight);
                await delay(350);
                const currentHeight = document.body.scrollHeight;
                if (currentHeight === previousHeight) {
                  break;
                }
                previousHeight = currentHeight;
              }
              window.scrollTo(0, 0);
              await delay(150);
            }
            """
        )

    @staticmethod
    def _extract_browser_links(page: object) -> tuple[str, ...]:
        try:
            raw_links = page.evaluate(
                """
                () => {
                  const attributes = ["data-href", "data-url", "data-link", "to", "routerlink"];
                  const values = new Set();
                  const selectors = attributes.map((name) => `[${name}]`).join(",");
                  for (const element of document.querySelectorAll("a[href], area[href]")) {
                    values.add(element.getAttribute("href"));
                  }
                  for (const element of document.querySelectorAll(selectors)) {
                    for (const attribute of attributes) {
                      const value = element.getAttribute(attribute);
                      if (value) {
                        values.add(value);
                      }
                    }
                  }
                  for (const element of document.querySelectorAll("[onclick]")) {
                    const value = element.getAttribute("onclick") || "";
                    const navigationPattern =
                      /(?:location\\.href|location\\.assign|window\\.open)\\(['"]([^'"]+)['"]/i;
                    const match = value.match(navigationPattern);
                    if (match) {
                      values.add(match[1]);
                    }
                  }
                  return Array.from(values);
                }
                """
            )
        except Exception:  # noqa: BLE001
            return ()
        links: set[str] = set()
        for raw_link in raw_links:
            if not isinstance(raw_link, str):
                continue
            normalized = normalize_url(page.url, raw_link)
            if normalized:
                links.add(normalized)
        return tuple(sorted(links))


class Crawler:
    def __init__(
        self,
        config: ScanConfig,
        client: HttpClient,
        renderer: PageRenderer | None = None,
    ) -> None:
        self._config = config
        self._client = client
        self._renderer = renderer

    def crawl(self) -> CrawlResult:
        start_url = normalize_url(self._config.target_url, self._config.target_url)
        if start_url is None:
            raise ValueError("Target URL must be an absolute http(s) URL")

        queue: deque[tuple[str, int]] = deque([(start_url, 0)])
        visited: set[str] = set()
        pages: list[Page] = []
        errors: dict[str, str] = {}

        try:
            while queue and len(pages) < self._config.max_pages:
                url, depth = queue.popleft()
                if url in visited:
                    continue
                visited.add(url)

                try:
                    page = self._crawl_page(url, errors)
                except requests.RequestException as exc:
                    errors[url] = str(exc)
                    continue

                if page is None:
                    continue

                pages.append(page)

                if depth >= self._config.max_depth:
                    continue

                for link in page.links:
                    if link not in visited and is_in_scope(
                        start_url,
                        link,
                        include_subdomains=self._config.include_subdomains,
                    ):
                        queue.append((link, depth + 1))
        finally:
            if self._renderer is not None:
                self._renderer.close()

        return CrawlResult(pages=pages, errors=errors)

    def _crawl_page(self, url: str, errors: dict[str, str]) -> Page | None:
        engine = self._normalized_engine()
        if engine == "playwright":
            return self._render_page(url, errors)

        response = self._client.get(url)
        page = _page_from_response(response)

        if engine == "auto" and _should_render_with_playwright(response, page):
            rendered_page = self._render_page(url, errors)
            if rendered_page is not None:
                return rendered_page

        return page

    def _render_page(self, url: str, errors: dict[str, str]) -> Page | None:
        try:
            renderer = self._renderer or PlaywrightPageRenderer(self._config)
            if self._renderer is None:
                self._renderer = renderer
            rendered = renderer.render(url)
        except Exception as exc:  # noqa: BLE001
            errors[url] = f"Playwright render failed: {exc}"
            return None

        if _looks_like_challenge_page(rendered.url, rendered.html):
            errors[url] = (
                "Rendered page appears to be an anti-bot or browser challenge page. "
                "The scan result is limited because the target did not expose the real application."
            )

        return _page_from_response(
            HttpResponse(
                url=rendered.url,
                status_code=rendered.status_code,
                headers=rendered.headers,
                text=rendered.html,
            ),
            extra_links=rendered.discovered_links,
        )

    def _normalized_engine(self) -> str:
        engine = self._config.crawl_engine.lower()
        return engine if engine in {"requests", "playwright", "auto"} else "auto"


def _page_from_response(
    response: HttpResponse,
    extra_links: tuple[str, ...] = (),
) -> Page:
    content_type = response.headers.get("content-type", "")
    is_html = "html" in content_type.lower() or response.text.lstrip().startswith("<")
    html_links = extract_links(response.url, response.text) if is_html else ()
    links = tuple(sorted(set(html_links).union(extra_links)))
    forms = extract_forms(response.url, response.text) if is_html else ()

    return Page(
        url=response.url,
        status_code=response.status_code,
        headers=response.headers,
        title=extract_title(response.text) if is_html else "",
        links=links,
        forms=forms,
    )


def _should_render_with_playwright(response: HttpResponse, page: Page) -> bool:
    if page.links or page.forms:
        return False
    content_type = response.headers.get("content-type", "")
    if "html" not in content_type.lower() and not response.text.lstrip().startswith("<"):
        return False

    html = response.text.lower()
    spa_markers = (
        "<script",
        'id="root"',
        'id="app"',
        "data-reactroot",
        "__next",
        "ng-version",
        "window.__",
    )
    return any(marker in html for marker in spa_markers)


def _looks_like_challenge_page(url: str, html: str) -> bool:
    normalized = f"{url}\n{html}".lower()
    challenge_markers = (
        "antibot",
        "/challenge/",
        "/challenges/",
        "captcha",
        "checking your browser",
        "just a moment",
        "enable javascript and cookies",
        "почти готово",
    )
    return any(marker in normalized for marker in challenge_markers)
