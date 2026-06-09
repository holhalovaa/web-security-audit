from collections.abc import Mapping

from websec_audit.crawler import Crawler
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
