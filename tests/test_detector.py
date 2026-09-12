from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from wpsscanner.http_client import ScannerHttpClient
from wpsscanner.models import HttpSnapshot
from wpsscanner.path_detector import PathDetector, build_baseline
from wpsscanner.utils import parse_status_codes


class DemoHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path == "/admin/panel":
            self._send(200, "<title>Control panel</title><main>unique administration dashboard</main>")
        elif self.path == "/private":
            self._send(403, "<title>Forbidden</title>authentication required")
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
        elif self.path.startswith("/admin/"):
            self._send(200, f"<title>Missing</title><p>Unknown {self.path} at 2026-01-01 10:20:30</p>")
        else:
            self._send(200, f"<title>Not found</title><p>Unknown {self.path} at 2026-01-01 10:20:30</p>")

    def _send(self, status, body):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture()
def demo_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_detector_filters_scoped_soft404_and_keeps_useful_statuses(demo_url):
    client = ScannerHttpClient()
    try:
        detector = PathDetector(
            demo_url,
            client=client,
            accepted_statuses=parse_status_codes("200,302,403"),
        )
        results, recursion = detector.run(4, ["missing", "admin/missing", "admin/panel", "private", "redirect"])
    finally:
        client.close()

    by_path = {result.path: result for result in results}
    assert set(by_path) == {"admin/panel", "private", "redirect"}
    assert by_path["admin/panel"].title == "Control panel"
    assert by_path["private"].status == 403
    assert by_path["redirect"].redirect_url == f"{demo_url}login"
    assert recursion == [f"{demo_url}admin/"]


def test_redirect_only_baseline_is_stable_and_matches():
    samples = [
        HttpSnapshot(f"https://example.test/miss-{index}", f"https://example.test/miss-{index}",
                     302, {"location": "/login"}, "", 0.01)
        for index in range(3)
    ]
    baseline = build_baseline("/", samples, 0.72)
    candidate = HttpSnapshot("https://example.test/unknown", "https://example.test/unknown",
                             302, {"Location": "/login"}, "", 0.01)
    assert baseline.stable
    assert baseline.matches(candidate, 0.82)


def test_single_successful_baseline_sample_is_not_stable():
    baseline = build_baseline(
        "/",
        [HttpSnapshot("https://example.test/a", "https://example.test/a", 200, {}, "missing", 0.01)],
        0.72,
    )
    assert not baseline.stable
