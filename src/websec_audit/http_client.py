from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

import requests


@dataclass(frozen=True)
class HttpResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    text: str


class HttpClient(Protocol):
    def get(self, url: str) -> HttpResponse:
        raise NotImplementedError

    def submit(self, method: str, url: str, data: Mapping[str, str]) -> HttpResponse:
        raise NotImplementedError


class RequestsHttpClient:
    def __init__(self, timeout: float, user_agent: str, verify_tls: bool = True) -> None:
        self._timeout = timeout
        self._verify_tls = verify_tls
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": user_agent})

    def get(self, url: str) -> HttpResponse:
        response = self._session.get(url, timeout=self._timeout, verify=self._verify_tls)
        return self._adapt(response)

    def submit(self, method: str, url: str, data: Mapping[str, str]) -> HttpResponse:
        normalized_method = method.lower()
        if normalized_method == "get":
            response = self._session.get(
                url,
                params=data,
                timeout=self._timeout,
                verify=self._verify_tls,
            )
        else:
            response = self._session.request(
                normalized_method,
                url,
                data=data,
                timeout=self._timeout,
                verify=self._verify_tls,
            )
        return self._adapt(response)

    @staticmethod
    def _adapt(response: requests.Response) -> HttpResponse:
        return HttpResponse(
            url=response.url,
            status_code=response.status_code,
            headers=dict(response.headers),
            text=response.text,
        )
