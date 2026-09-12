from __future__ import annotations

import threading
import time

import requests

from .models import HttpSnapshot

DEFAULT_HEADERS = {
    "User-Agent": "wpsscanner/0.2.0 (+https://github.com/kaixliu56/wpsscanner)",
    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.8,en;q=0.5",
}


class RateLimiter:
    def __init__(self, requests_per_second: float = 0.0) -> None:
        self.interval = 1.0 / requests_per_second if requests_per_second > 0 else 0.0
        self._next_request = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        if not self.interval:
            return
        with self._lock:
            now = time.monotonic()
            delay = self._next_request - now
            if delay > 0:
                time.sleep(delay)
                now = time.monotonic()
            self._next_request = max(now, self._next_request) + self.interval


class ScannerHttpClient:
    def __init__(self, *, timeout: float = 6.0, connect_timeout: float = 3.0,
                 verify_tls: bool = True, follow_redirects: bool = False,
                 headers: dict[str, str] | None = None, cookie: str | None = None,
                 proxy: str | None = None, rate: float = 0.0,
                 max_body_bytes: int = 256 * 1024) -> None:
        self.timeout = (connect_timeout, timeout)
        self.verify_tls = verify_tls
        self.follow_redirects = follow_redirects
        self.headers = {**DEFAULT_HEADERS, **(headers or {})}
        if cookie:
            self.headers["Cookie"] = cookie
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.max_body_bytes = max_body_bytes
        self.rate_limiter = RateLimiter(rate)
        self._local = threading.local()
        self._sessions: list[requests.Session] = []
        self._sessions_lock = threading.Lock()

    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            session.headers.update(self.headers)
            self._local.session = session
            with self._sessions_lock:
                self._sessions.append(session)
        return session

    def fetch(self, url: str) -> HttpSnapshot:
        self.rate_limiter.wait()
        started = time.monotonic()
        try:
            with self._session().get(url, timeout=self.timeout, allow_redirects=self.follow_redirects,
                                     verify=self.verify_tls, proxies=self.proxies, stream=True) as response:
                chunks: list[bytes] = []
                received = 0
                for chunk in response.iter_content(chunk_size=16 * 1024):
                    if not chunk:
                        continue
                    remaining = self.max_body_bytes - received
                    if remaining <= 0:
                        break
                    chunks.append(chunk[:remaining])
                    received += min(len(chunk), remaining)
                raw = b"".join(chunks)
                body = raw.decode(response.encoding or "utf-8", errors="replace")
                return HttpSnapshot(url=url, final_url=response.url, status=response.status_code,
                                    headers=dict(response.headers), body=body,
                                    elapsed=time.monotonic() - started)
        except requests.RequestException as exc:
            return HttpSnapshot(url=url, final_url=url, status=None, headers={}, body="",
                                elapsed=time.monotonic() - started,
                                error=f"{type(exc).__name__}: {exc}")

    def close(self) -> None:
        with self._sessions_lock:
            for session in self._sessions:
                session.close()
            self._sessions.clear()
