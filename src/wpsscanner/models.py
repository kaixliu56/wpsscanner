from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Mapping
from urllib.parse import urljoin, urlsplit

from .utils import extract_title, normalize_body, text_similarity


@dataclass(frozen=True)
class HttpSnapshot:
    url: str
    final_url: str
    status: int | None
    headers: Mapping[str, str]
    body: str
    elapsed: float
    error: str | None = None

    @property
    def redirect_url(self) -> str:
        if self.final_url != self.url:
            return self.final_url
        location = next(
            (value for name, value in self.headers.items() if name.lower() == "location"),
            "",
        )
        return urljoin(self.url, location) if location else ""


@dataclass(frozen=True)
class Fingerprint:
    status: int | None
    length: int
    title: str
    redirect_path: str
    body: str

    @classmethod
    def from_snapshot(cls, snapshot: HttpSnapshot) -> "Fingerprint":
        redirect_path = ""
        if snapshot.redirect_url:
            parts = urlsplit(snapshot.redirect_url)
            redirect_path = parts.path.rstrip("/") or "/"
        return cls(
            status=snapshot.status,
            length=len(snapshot.body.encode("utf-8", errors="replace")),
            title=extract_title(snapshot.body).lower(),
            redirect_path=redirect_path,
            body=normalize_body(snapshot.body, request_path=urlsplit(snapshot.url).path),
        )

    def similarity(self, other: "Fingerprint") -> float:
        largest = max(self.length, other.length, 1)
        weighted_scores = [
            (0.20, max(0.0, 1.0 - abs(self.length - other.length) / largest)),
        ]
        if self.status is not None or other.status is not None:
            weighted_scores.append((0.10, 1.0 if self.status == other.status else 0.0))
        if self.body or other.body:
            weighted_scores.append((0.55, text_similarity(self.body, other.body)))
        if self.title or other.title:
            weighted_scores.append((0.10, text_similarity(self.title, other.title)))
        if self.redirect_path or other.redirect_path:
            weighted_scores.append(
                (0.05, 1.0 if self.redirect_path == other.redirect_path else 0.0)
            )
        total_weight = sum(weight for weight, _ in weighted_scores)
        return sum(weight * score for weight, score in weighted_scores) / total_weight


@dataclass(frozen=True)
class Baseline:
    scope: str
    samples: tuple[Fingerprint, ...]
    representative: Fingerprint | None
    consistency: float
    stable: bool
    inherited_from: str | None = None

    def matches(
        self,
        snapshot: HttpSnapshot,
        threshold: float,
        *,
        treat_hard_not_found: bool = True,
    ) -> bool:
        if treat_hard_not_found and snapshot.status in {404, 410}:
            return True
        if not self.stable or not self.representative:
            return False
        candidate = Fingerprint.from_snapshot(snapshot)
        return max((candidate.similarity(sample) for sample in self.samples), default=0.0) >= threshold


@dataclass(frozen=True)
class ScanResult:
    url: str
    path: str
    scope: str
    status: int
    length: int
    title: str
    redirect_url: str
    elapsed_ms: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
