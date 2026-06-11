from collections.abc import Mapping

import pytest
import requests

from websec_audit.crawler import Crawler, PlaywrightPageRenderer, RenderedResponse
from websec_audit.http_client import HttpResponse
from websec_audit.models import ScanConfig


class FakeClient:
    def __init__(self) -> None:
        self.seen: list[str] = []

    def get(self, url: str) -> HttpResponse:
        self.seen.append(url)
        pages = {
            "https://example.test/": """
                <html>
                  <a href="/about">About</a>
                  <a href="https://other.test/">Other</a>
                </html>
            """,
            "https://example.test/about": "<html><title>About</title></html>",
        }
        return HttpResponse(
            url=url,
            status_code=200,
            headers={"content-type": "text/html"},
            text=pages[url],
        )

    def submit(self, method: str, url: str, data: Mapping[str, str]) -> HttpResponse:
        raise AssertionError("crawler must not submit forms")


def test_crawler_respects_same_host_scope() -> None:
    client = FakeClient()
    crawler = Crawler(
        ScanConfig(target_url="https://example.test/", max_depth=1, max_pages=10),
        client,
    )

    result = crawler.crawl()

    assert [page.url for page in result.pages] == [
        "https://example.test/",
        "https://example.test/about",
    ]
    assert "https://other.test/" not in client.seen


def test_crawler_records_fetch_errors() -> None:
    class ErrorClient(FakeClient):
        def get(self, url: str) -> HttpResponse:
            raise requests.RequestException("connection refused")

    result = Crawler(
        ScanConfig(target_url="https://example.test/", max_depth=0),
        ErrorClient(),
    ).crawl()

    assert result.pages == []
    assert result.errors == {"https://example.test/": "connection refused"}


def test_crawler_handles_non_html_responses() -> None:
    class JsonClient(FakeClient):
        def get(self, url: str) -> HttpResponse:
            return HttpResponse(
                url=url,
                status_code=200,
                headers={"content-type": "application/json"},
                text='{"ok": true}',
            )

    result = Crawler(
        ScanConfig(target_url="https://example.test/api", max_depth=1),
        JsonClient(),
    ).crawl()

    assert len(result.pages) == 1
    assert result.pages[0].links == ()
    assert result.pages[0].forms == ()


def test_crawler_extracts_links_from_json_responses() -> None:
    class JsonClient(FakeClient):
        def get(self, url: str) -> HttpResponse:
            pages = {
                "https://example.test/api": '{"items": [{"href": "/products/42"}]}',
                "https://example.test/products/42": '{"ok": true}',
            }
            return HttpResponse(
                url=url,
                status_code=200,
                headers={"content-type": "application/json"},
                text=pages[url],
            )

    result = Crawler(
        ScanConfig(target_url="https://example.test/api", max_depth=1, max_pages=10),
        JsonClient(),
    ).crawl()

    assert [page.url for page in result.pages] == [
        "https://example.test/api",
        "https://example.test/products/42",
    ]


def test_playwright_renderer_extracts_links_from_json_network_response() -> None:
    class FakeResponse:
        headers = {"content-type": "application/json"}
        url = "https://example.test/api/menu"

        def text(self) -> str:
            return '{"next": "/dashboard", "external": "https://other.test/path"}'

    links = PlaywrightPageRenderer._extract_response_links(FakeResponse())

    assert links == {
        "https://example.test/dashboard",
        "https://other.test/path",
    }


def test_crawler_rejects_invalid_target_url() -> None:
    with pytest.raises(ValueError):
        Crawler(ScanConfig(target_url="mailto:admin@example.test"), FakeClient()).crawl()


def test_crawler_uses_playwright_renderer_for_spa_pages() -> None:
    class SpaClient(FakeClient):
        def get(self, url: str) -> HttpResponse:
            self.seen.append(url)
            return HttpResponse(
                url=url,
                status_code=200,
                headers={"content-type": "text/html"},
                text=(
                    '<html><head><script src="/app.js"></script></head>'
                    '<body><div id="app"></div></body></html>'
                ),
            )

    class FakeRenderer:
        closed = False

        def render(self, url: str) -> RenderedResponse:
            assert url == "https://example.test/"
            return RenderedResponse(
                url=url,
                status_code=200,
                headers={"content-type": "text/html"},
                html="""
                    <html>
                      <title>SPA</title>
                      <a href="/dashboard">Dashboard</a>
                      <form method="post" action="/login"><input name="email"></form>
                    </html>
                """,
            )

        def close(self) -> None:
            self.closed = True

    renderer = FakeRenderer()
    result = Crawler(
        ScanConfig(target_url="https://example.test/", max_depth=0),
        SpaClient(),
        renderer=renderer,
    ).crawl()

    assert result.errors == {}
    assert result.pages[0].title == "SPA"
    assert result.pages[0].links == ("https://example.test/dashboard",)
    assert result.pages[0].forms[0].action == "https://example.test/login"
    assert renderer.closed is True


def test_crawler_can_force_playwright_engine_without_requests() -> None:
    class FailingClient(FakeClient):
        def get(self, url: str) -> HttpResponse:
            raise AssertionError("requests engine must not be used")

    class FakeRenderer:
        def render(self, url: str) -> RenderedResponse:
            return RenderedResponse(
                url=url,
                status_code=200,
                headers={"content-type": "text/html"},
                html="<html><title>Rendered</title></html>",
            )

        def close(self) -> None:
            return None

    result = Crawler(
        ScanConfig(target_url="https://example.test/", crawl_engine="playwright"),
        FailingClient(),
        renderer=FakeRenderer(),
    ).crawl()

    assert [page.title for page in result.pages] == ["Rendered"]


def test_crawler_uses_playwright_discovered_links() -> None:
    class FailingClient(FakeClient):
        def get(self, url: str) -> HttpResponse:
            raise AssertionError("requests engine must not be used")

    class FakeRenderer:
        def render(self, url: str) -> RenderedResponse:
            pages = {
                "https://example.test/": RenderedResponse(
                    url=url,
                    status_code=200,
                    headers={"content-type": "text/html"},
                    html="<html><title>Home</title></html>",
                    discovered_links=(
                        "https://example.test/catalog",
                        "https://other.test/ignored",
                    ),
                ),
                "https://example.test/catalog": RenderedResponse(
                    url=url,
                    status_code=200,
                    headers={"content-type": "text/html"},
                    html="<html><title>Catalog</title></html>",
                ),
            }
            return pages[url]

        def close(self) -> None:
            return None

    result = Crawler(
        ScanConfig(
            target_url="https://example.test/",
            max_depth=1,
            max_pages=10,
            crawl_engine="playwright",
        ),
        FailingClient(),
        renderer=FakeRenderer(),
    ).crawl()

    assert [page.url for page in result.pages] == [
        "https://example.test/",
        "https://example.test/catalog",
    ]


def test_crawler_records_browser_challenge_pages_without_dropping_page() -> None:
    class FailingClient(FakeClient):
        def get(self, url: str) -> HttpResponse:
            raise AssertionError("requests engine must not be used")

    class FakeRenderer:
        def render(self, url: str) -> RenderedResponse:
            return RenderedResponse(
                url=url,
                status_code=200,
                headers={"content-type": "text/html"},
                html="<html><title>Just a moment</title><body>Checking your browser</body></html>",
            )

        def close(self) -> None:
            return None

    result = Crawler(
        ScanConfig(target_url="https://example.test/", crawl_engine="playwright"),
        FailingClient(),
        renderer=FakeRenderer(),
    ).crawl()

    assert len(result.pages) == 1
    assert "anti-bot or browser challenge" in result.errors["https://example.test/"]
