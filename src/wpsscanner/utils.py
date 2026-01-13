import random
import string
import sys
from difflib import SequenceMatcher
import requests
from urllib.parse import urljoin
from collections import defaultdict
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3 import disable_warnings
from tqdm import tqdm
import argparse
import os
from pyfiglet import Figlet


def logo():
    f = Figlet()
    logo_str = f.renderText("Web_path_scan\n")
    print(logo_str)


def random_path(length=12):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def stable_body(body, size=1024):
    """只取前 1KB，规避动态内容"""
    return body[:size] if body else ""


def path_scope(path):
    if "/" in path:
        parts = path.strip("/").split("/")
        if len(parts) >= 1 and parts[0]:
            return f"{parts[0]}/"
        return "/"
    else:
        return "/"


def quick_similarity(text1, text2, threshold=0.7):
    if not text1 or not text2:
        return False

    seq = SequenceMatcher(None, text1, text2)
    if seq.ratio() < threshold:
        return False

    return True


def fetch(url, timeout=6):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:146.0) Gecko/20100101 Firefox/146.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip, deflate, br",
    }
    try:
        if url.startswith("http://"):
            r = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
            return r.status_code, r.text
        if url.startswith("https://"):
            r = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True, verify=False)
            return r.status_code, r.text
    except Exception:
        return None, None


def is_fake_404(resp_body, fingerprints):
    body = stable_body(resp_body)

    for fp in fingerprints:

        if quick_similarity(body, fp):
            return True

    return False


def output(valid_paths, output):
    print("\n[*] valid paths:")
    if output:
        with open(output, "a", encoding="utf-8") as f:
            if valid_paths:
                for path in valid_paths:
                    f.write(path + "\n")
                    print(path)
    else:
        if valid_paths:
            for path in valid_paths:
                print(path)

