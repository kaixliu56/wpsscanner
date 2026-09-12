from __future__ import annotations

import html
import random
import re
import string
from difflib import SequenceMatcher
from urllib.parse import urlsplit, urlunsplit

_SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b[^>]*>.*?</\1>", re.I | re.S)
_TAG_RE = re.compile(r"<[^>]+>")
_SPACE_RE = re.compile(r"\s+")
_UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.I)
_LONG_HEX_RE = re.compile(r"\b[0-9a-f]{16,}\b", re.I)
_LONG_NUMBER_RE = re.compile(r"\b\d{6,}\b")
_ISO_TIME_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?Z?\b")
_PROBE_RE = re.compile(r"\.wpsscanner-404-[a-z0-9]{16}", re.I)
_TITLE_RE = re.compile(r"<title\b[^>]*>(.*?)</title>", re.I | re.S)


def random_path(length: int = 16) -> str:
    token = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return f".wpsscanner-404-{token}"


def normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("target URL is empty")
    if "://" not in target:
        target = f"http://{target}"
    parts = urlsplit(target)
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        raise ValueError(f"invalid HTTP(S) URL: {target}")
    path = parts.path.rstrip("/") + "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc, path, parts.query, ""))


def normalize_body(body: str, limit: int = 16_384, request_path: str = "") -> str:
    """Return stable visible text while replacing common dynamic tokens."""
    if not body:
        return ""
    text = _SCRIPT_STYLE_RE.sub(" ", body[:limit])
    text = _TAG_RE.sub(" ", text)
    text = html.unescape(text).lower()
    # Error templates frequently echo the requested path. Replace each
    # response's own path so random baselines also match ordinary misses.
    if request_path and request_path != "/":
        text = text.replace(request_path.lower(), "<request-path>")
    text = _PROBE_RE.sub("<probe>", text)
    text = _UUID_RE.sub("<uuid>", text)
    text = _ISO_TIME_RE.sub("<time>", text)
    text = _LONG_HEX_RE.sub("<hex>", text)
    text = _LONG_NUMBER_RE.sub("<number>", text)
    return _SPACE_RE.sub(" ", text).strip()


def extract_title(body: str) -> str:
    match = _TITLE_RE.search(body or "")
    if not match:
        return ""
    return _SPACE_RE.sub(" ", html.unescape(match.group(1))).strip()[:256]


def path_scope(path: str) -> str:
    clean = path.strip().lstrip("/")
    if "/" not in clean:
        return "/"
    first = clean.split("/", 1)[0]
    return f"{first}/" if first else "/"


def text_similarity(left: str, right: str) -> float:
    if not left or not right:
        return 0.0
    if left == right:
        return 1.0
    return SequenceMatcher(None, left, right, autojunk=False).ratio()


def parse_status_codes(value: str) -> set[int]:
    statuses: set[int] = set()
    for raw_part in value.split(","):
        part = raw_part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError(f"invalid status range: {part}")
            statuses.update(range(start, end + 1))
        else:
            statuses.add(int(part))
    if not statuses or any(code < 100 or code > 599 for code in statuses):
        raise ValueError(f"invalid status list: {value}")
    return statuses


def parse_headers(values: list[str] | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for value in values or []:
        if ":" not in value:
            raise ValueError(f"header must use 'Name: value': {value}")
        name, content = value.split(":", 1)
        if not name.strip():
            raise ValueError("header name cannot be empty")
        headers[name.strip()] = content.strip()
    return headers
