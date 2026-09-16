from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from threading import Event

from tqdm import tqdm

from .http_client import ScannerHttpClient
from .models import ScanResult
from .path_detector import PathDetector
from .utils import normalize_target, parse_headers, parse_status_codes

DEFAULT_STATUSES = "200-299,301,302,307,308,401,403,405"


def logo() -> None:
    print("wpsscanner 0.2.0 — scoped soft-404 path scanner")


@dataclass
class ScanContext:
    thread: int
    web_paths: list[str]
    recursion: bool
    output: str | None
    output_format: str
    detector_options: dict[str, object]
    client: ScannerHttpClient
    results: list[ScanResult] = field(default_factory=list)
    stop_event: Event = field(default_factory=Event)

    def add_results(self, results: list[ScanResult]) -> None:
        self.results.extend(results)

    def output_results(self) -> None:
        unique = sorted({item.url: item for item in self.results}.values(), key=lambda item: item.url)
        lines: list[str] = []
        for item in unique:
            if self.output_format == "jsonl":
                lines.append(json.dumps(item.to_dict(), ensure_ascii=False))
            else:
                suffix = f" -> {item.redirect_url}" if item.redirect_url else ""
                title = f" [{item.title}]" if item.title else ""
                lines.append(f"{item.status}\t{item.length}\t{item.url}{suffix}{title}")
        print(f"\n[*] valid paths: {len(lines)}")
        for line in lines:
            print(line)
        if self.output:
            with open(self.output, "w", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + ("\n" if lines else ""))
            print(f"\n[*] results written to {os.path.abspath(self.output)}")


def read_list(path: str, label: str) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return list(dict.fromkeys(line.strip() for line in handle
                                      if line.strip() and not line.lstrip().startswith("#")))
    except OSError as exc:
        raise ValueError(f"cannot read {label} file {path}: {exc}") from exc


def scan_target(target: str, context: ScanContext) -> None:
    normalized = normalize_target(target)
    print(f"\n[*] scanning target: {normalized}")
    detector = PathDetector(normalized, client=context.client, stop_event=context.stop_event,
                            **context.detector_options)
    results, recursion_targets = detector.run(context.thread, context.web_paths)
    context.add_results(results)
    if context.recursion:
        for recursion_target in recursion_targets:
            if context.stop_event.is_set():
                break
            print(f"\n[*] recursive scan: {recursion_target}")
            child = PathDetector(recursion_target, client=context.client,
                                 stop_event=context.stop_event, **context.detector_options)
            child_results, _ = child.run(context.thread, context.web_paths)
            context.add_results(child_results)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Web path scanner with scoped soft-404 detection")
    targets = parser.add_mutually_exclusive_group(required=True)
    targets.add_argument("-u", "--target", help="target URL")
    targets.add_argument("-l", "--list", help="file containing target URLs")
    parser.add_argument("-w", "--wordlist", required=True, help="path wordlist")
    parser.add_argument("-t", "--thread", type=int, default=20, help="worker threads (default: 20)")
    parser.add_argument("-r", "--recursion", action="store_true", help="scan discovered directories once")
    parser.add_argument("-o", "--output", help="output file")
    parser.add_argument("--format", choices=("text", "jsonl"), default="text")
    parser.add_argument("--status", default=DEFAULT_STATUSES,
                        help=f"accepted codes (default: {DEFAULT_STATUSES})")
    parser.add_argument("--timeout", type=float, default=6.0, help="read timeout in seconds")
    parser.add_argument("--connect-timeout", type=float, default=3.0)
    parser.add_argument("--rate", type=float, default=0.0,
                        help="global requests/second; 0 is unlimited")
    parser.add_argument("-H", "--header", action="append",
                        help="custom header, repeatable: 'Name: value'")
    parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument("--proxy", help="HTTP(S) proxy URL")
    parser.add_argument("--insecure", action="store_true",
                        help="disable TLS certificate verification")
    parser.add_argument("--follow-redirects", action="store_true")
    parser.add_argument("--baseline-samples", type=int, default=3)
    parser.add_argument("--soft404-threshold", type=float, default=0.82)
    parser.add_argument("--baseline-consistency", type=float, default=0.72)
    parser.add_argument("--max-errors", type=int, default=20,
                        help="stop after consecutive network errors")
    parser.add_argument("--debug", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    logo()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.thread < 1 or args.timeout <= 0 or args.connect_timeout <= 0 or args.rate < 0:
            raise ValueError("thread/timeouts must be positive and rate cannot be negative")
        if args.max_errors < 1:
            raise ValueError("max errors must be at least 1")
        if args.baseline_samples < 2:
            raise ValueError("baseline samples must be at least 2")
        if not 0.0 <= args.soft404_threshold <= 1.0:
            raise ValueError("soft404 threshold must be between 0 and 1")
        if not 0.0 <= args.baseline_consistency <= 1.0:
            raise ValueError("baseline consistency must be between 0 and 1")
        web_paths = read_list(args.wordlist, "wordlist")
        if not web_paths:
            raise ValueError("wordlist contains no usable paths")
        urls = [args.target] if args.target else read_list(args.list, "target list")
        if not urls:
            raise ValueError("target list contains no usable URLs")
        statuses = parse_status_codes(args.status)
        headers = parse_headers(args.header)
    except ValueError as exc:
        parser.error(str(exc))

    client = ScannerHttpClient(timeout=args.timeout, connect_timeout=args.connect_timeout,
                               verify_tls=not args.insecure,
                               follow_redirects=args.follow_redirects, headers=headers,
                               cookie=args.cookie, proxy=args.proxy, rate=args.rate)
    context = ScanContext(thread=args.thread, web_paths=web_paths, recursion=args.recursion,
                          output=args.output, output_format=args.format, client=client,
                          detector_options={"accepted_statuses": statuses,
                                            "baseline_samples": args.baseline_samples,
                                            "soft404_threshold": args.soft404_threshold,
                                            "baseline_consistency": args.baseline_consistency,
                                            "max_consecutive_errors": args.max_errors,
                                            "debug": args.debug})
    try:
        for url in tqdm(urls, desc="Targets", disable=len(urls) == 1, position=1):
            if context.stop_event.is_set():
                break
            scan_target(url, context)
    except KeyboardInterrupt:
        context.stop_event.set()
        print("\n[*] interrupted; stopping active requests...")
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    finally:
        client.close()
    context.output_results()
    return 130 if context.stop_event.is_set() else 0


if __name__ == "__main__":
    raise SystemExit(main())
