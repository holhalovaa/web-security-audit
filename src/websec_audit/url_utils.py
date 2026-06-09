from __future__ import annotations

from urllib.parse import urldefrag, urljoin, urlparse, urlunparse


def normalize_url(base_url: str, candidate: str) -> str | None:
    if not candidate:
        return None
    absolute = urljoin(base_url, candidate.strip())
    absolute, _fragment = urldefrag(absolute)
    parsed = urlparse(absolute)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    normalized = parsed._replace(path=parsed.path or "/")
    return urlunparse(normalized)


def is_in_scope(target_url: str, candidate_url: str, include_subdomains: bool = False) -> bool:
    target_host = urlparse(target_url).hostname or ""
    candidate_host = urlparse(candidate_url).hostname or ""
    if not target_host or not candidate_host:
        return False
    if include_subdomains:
        return candidate_host == target_host or candidate_host.endswith(f".{target_host}")
    return candidate_host == target_host
