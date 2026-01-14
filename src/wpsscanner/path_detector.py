from wpsscanner.utils import *


class PathDetector:
    def __init__(self, target):
        self.scope_stats = defaultdict(lambda: {
            "has_baseline": False,
            "already_flag": False,
            "fingerprints": None,
            "lock": Lock()
        })
        self.valid_paths = []
        self.valid_lock = Lock()
        self.print_lock = Lock()
        self.target = target
        self.recursion_path = set()

    def detect_fake_404_for_scope(self, base_url, scope):
        fingerprints = []
        if scope == "/":
            target = base_url
        else:
            target = urljoin(base_url, scope)

        for _ in range(5):
            rand = random_path()
            url = urljoin(target, rand)
            code, body = fetch(url)

            if code == 200 and body:
                fingerprints.append(stable_body(body))

        return fingerprints if len(fingerprints) > 2 else None

    def scan_one_path(self, path):
        scope = path_scope(path)
        state = self.scope_stats[scope]

        # ===== 基线建立（受控）=====
        if not state["already_flag"]:
            with state["lock"]:
                if not state["already_flag"]:
                    fingerprints = self.detect_fake_404_for_scope(self.target, scope)
                    if fingerprints:
                        state["fingerprints"] = fingerprints
                        state["has_baseline"] = True
                    state["already_flag"] = True

        # ===== 发请求 =====
        url = urljoin(self.target, path)
        code, body = fetch(url)

        if code in [401, 403]:
            with self.valid_lock:
                self.recursion_path.add(scope)

        if code == 200 and body:
            if state["has_baseline"]:
                if not is_fake_404(body, state["fingerprints"]):
                    with self.valid_lock:
                        self.valid_paths.append(path)
                        tqdm.write(urljoin(self.target, path))
                        self.recursion_path.add(scope)
            else:
                with self.valid_lock:
                    self.valid_paths.append(path)
                    tqdm.write(urljoin(self.target, path))
                    self.recursion_path.add(scope)

    def run(self, thread_num, webpaths):
        max_workers = thread_num  # 建议 5~15 之间
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self.scan_one_path, path) for path in webpaths]
            for _ in tqdm(
                    as_completed(futures),
                    total=len(futures),
                    desc="Scanning",
                    ncols=80,
                    leave=False,
                    position=0
            ):
                pass

            result_path = []
            recursion_paths = []
            if self.valid_paths:
                for path in self.valid_paths:
                    result_path.append(urljoin(self.target, path))
            if self.recursion_path:
                for path in self.recursion_path:
                    if path != "/":
                        recursion_paths.append(urljoin(self.target, path))
            return [result_path, recursion_paths]
