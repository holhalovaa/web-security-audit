import pytest

import websec_audit.http_client as http_client
from websec_audit.http_client import HttpClient, RequestsHttpClient


class ResponseStub:
    url = "https://example.test/result"
    status_code = 201
    headers = {"X-Test": "yes"}
    text = "body"


class SessionStub:
    def __init__(self) -> None:
        self.headers: dict[str, str] = {}
        self.get_calls: list[dict[str, object]] = []
        self.request_calls: list[dict[str, object]] = []

    def get(self, url: str, **kwargs):
        self.get_calls.append({"url": url, **kwargs})
        return ResponseStub()

    def request(self, method: str, url: str, **kwargs):
        self.request_calls.append({"method": method, "url": url, **kwargs})
        return ResponseStub()


class IncompleteClient(HttpClient):
    pass


def test_protocol_default_methods_raise_not_implemented() -> None:
    client = IncompleteClient()

    with pytest.raises(NotImplementedError):
        client.get("https://example.test/")
    with pytest.raises(NotImplementedError):
        client.submit("post", "https://example.test/", {})


def test_requests_http_client_get_and_submit(monkeypatch) -> None:
    session = SessionStub()
    monkeypatch.setattr(http_client.requests, "Session", lambda: session)

    client = RequestsHttpClient(timeout=2.5, user_agent="tests", verify_tls=False)

    assert session.headers["User-Agent"] == "tests"
    response = client.get("https://example.test/")
    assert response.url == "https://example.test/result"
    assert response.status_code == 201
    assert response.headers == {"X-Test": "yes"}
    assert response.text == "body"
    assert session.get_calls[0] == {
        "url": "https://example.test/",
        "timeout": 2.5,
        "verify": False,
    }

    get_response = client.submit("GET", "https://example.test/search", {"q": "x"})
    assert get_response.status_code == 201
    assert session.get_calls[1] == {
        "url": "https://example.test/search",
        "params": {"q": "x"},
        "timeout": 2.5,
        "verify": False,
    }

    post_response = client.submit("POST", "https://example.test/login", {"name": "a"})
    assert post_response.status_code == 201
    assert session.request_calls[0] == {
        "method": "post",
        "url": "https://example.test/login",
        "data": {"name": "a"},
        "timeout": 2.5,
        "verify": False,
    }
