from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from threading import Event, Lock
from urllib.parse import urljoin

from tqdm import tqdm

from .http_client import ScannerHttpClient
from .models import Baseline, Fingerprint, HttpSnapshot, ScanResult
from .utils import extract_title, normalize_target, path_scope, random_path


@dataclass
class _ScopeState:
    baseline: Baseline | None = None
    lock: Lock = field(default_factory=Lock)


def build_baseline(scope: str, snapshots: list[HttpSnapshot], consistency_threshold: float,
                   inherited_from: str | None = None) -> Baseline:
    fingerprints = tuple(Fingerprint.from_snapshot(item) for item in snapshots if not item.error)
    if not fingerprints:
        return Baseline(scope, (), None, 0.0, False, inherited_from)
    if len(fingerprints) == 1:
        return Baseline(scope, fingerprints, fingerprints[0], 0.0, False, inherited_from)

    averages: list[float] = []
    for index, current in enumerate(fingerprints):
        scores = [current.similarity(other) for other_index, other in enumerate(fingerprints)
                  if other_index != index]
        averages.append(sum(scores) / len(scores))
    representative_index = max(range(len(averages)), key=averages.__getitem__)
    consistency = averages[representative_index]
    return Baseline(scope=scope, samples=fingerprints,
                    representative=fingerprints[representative_index],
                    consistency=consistency, stable=consistency >= consistency_threshold,
                    inherited_from=inherited_from)


class PathDetector:
    def __init__(self, target: str, *, client: ScannerHttpClient,
                 accepted_statuses: set[int], stop_event: Event | None = None,
                 baseline_samples: int = 3, soft404_threshold: float = 0.82,
                 baseline_consistency: float = 0.72,
                 max_consecutive_errors: int = 20, debug: bool = False) -> None:
        self.target = normalize_target(target)
        self.client = client
        self.accepted_statuses = accepted_statuses
        self.stop_event = stop_event or Event()
        self.baseline_samples = max(2, baseline_samples)
        self.soft404_threshold = soft404_threshold
        self.baseline_consistency = baseline_consistency
        self.max_consecutive_errors = max_consecutive_errors
        self.debug = debug
        self._scope_states: dict[str, _ScopeState] = {}
        self._scope_states_lock = Lock()
        self._results: list[ScanResult] = []
        self._recursion_targets: set[str] = set()
        self._result_lock = Lock()
        self._error_lock = Lock()
        self._consecutive_errors = 0

    def _scope_state(self, scope: str) -> _ScopeState:
        with self._scope_states_lock:
            return self._scope_states.setdefault(scope, _ScopeState())

    def _probe(self, base_url: str) -> HttpSnapshot:
        return self.client.fetch(urljoin(base_url, random_path()))

    def _baseline_for(self, scope: str) -> Baseline:
        state = self._scope_state(scope)
        with state.lock:
            if state.baseline is not None:
                return state.baseline
            scope_url = self.target if scope == "/" else urljoin(self.target, scope)
            first = self._probe(scope_url)

            # Probe each directory once. Reuse the root baseline when behavior matches.
            if scope != "/":
                root = self._baseline_for("/")
                if not first.error and root.matches(
                    first,
                    self.soft404_threshold,
                    treat_hard_not_found=False,
                ):
                    state.baseline = Baseline(scope=scope, samples=root.samples,
                                              representative=root.representative,
                                              consistency=root.consistency, stable=root.stable,
                                              inherited_from="/")
                    return state.baseline

            snapshots = [first]
            snapshots.extend(self._probe(scope_url) for _ in range(self.baseline_samples - 1))
            state.baseline = build_baseline(scope, snapshots, self.baseline_consistency)
            if self.debug and not state.baseline.stable:
                tqdm.write(f"[debug] unstable soft-404 baseline: {self.target} scope={scope} "
                           f"consistency={state.baseline.consistency:.2f}")
            return state.baseline

    def _record_network_state(self, snapshot: HttpSnapshot) -> None:
        with self._error_lock:
            if snapshot.error:
                self._consecutive_errors += 1
                if self.debug:
                    tqdm.write(f"[debug] {snapshot.url}: {snapshot.error}")
                if self._consecutive_errors >= self.max_consecutive_errors:
                    self.stop_event.set()
                    tqdm.write(f"[!] stopping {self.target}: too many consecutive network errors")
            else:
                self._consecutive_errors = 0

    def scan_one_path(self, raw_path: str) -> None:
        if self.stop_event.is_set():
            return
        path = raw_path.strip().lstrip("/")
        if not path:
            return
        scope = path_scope(path)
        baseline = self._baseline_for(scope)
        if self.stop_event.is_set():
            return

        url = urljoin(self.target, path)
        snapshot = self.client.fetch(url)
        self._record_network_state(snapshot)
        if snapshot.error or snapshot.status not in self.accepted_statuses:
            return
        if baseline.matches(snapshot, self.soft404_threshold):
            if self.debug:
                tqdm.write(f"[debug] filtered soft-404: {url}")
            return

        result = ScanResult(url=url, path=path, scope=scope, status=snapshot.status,
                            length=len(snapshot.body.encode("utf-8", errors="replace")),
                            title=extract_title(snapshot.body), redirect_url=snapshot.redirect_url,
                            elapsed_ms=round(snapshot.elapsed * 1000))
        with self._result_lock:
            self._results.append(result)
            if scope != "/":
                self._recursion_targets.add(urljoin(self.target, scope))
        tqdm.write(f"[{result.status}] {result.url} ({result.length} B)")

    def run(self, thread_num: int, webpaths: list[str]) -> tuple[list[ScanResult], list[str]]:
        paths = list(dict.fromkeys(path.strip() for path in webpaths if path.strip()))
        workers = max(1, thread_num)
        pending: set[Future[None]] = set()
        iterator = iter(paths)
        executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="wpsscanner")
        progress = tqdm(total=len(paths), desc="Scanning", ncols=80, leave=False, position=0)
        try:
            for _ in range(min(len(paths), workers * 2)):
                pending.add(executor.submit(self.scan_one_path, next(iterator)))
            while pending and not self.stop_event.is_set():
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    future.result()
                    progress.update(1)
                    try:
                        pending.add(executor.submit(self.scan_one_path, next(iterator)))
                    except StopIteration:
                        pass
        except KeyboardInterrupt:
            self.stop_event.set()
        finally:
            for future in pending:
                future.cancel()
            executor.shutdown(wait=not self.stop_event.is_set(), cancel_futures=True)
            progress.close()

        results = sorted({result.url: result for result in self._results}.values(),
                         key=lambda result: result.url)
        return results, sorted(self._recursion_targets)
