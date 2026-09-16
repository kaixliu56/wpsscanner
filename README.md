# wpsscanner

`wpsscanner` is a small Web path scanner focused on reducing soft-404 false positives.
Version 0.2.0 keeps the original per-directory detection idea and adds layered baselines,
composite fingerprints, connection reuse, structured output, and tests.

Only scan systems you are authorized to assess.

## How soft-404 detection works

1. Build a root baseline from random, nonexistent paths.
2. Probe each first-level directory once.
3. Reuse the root baseline when the directory behaves the same; otherwise build a directory baseline.
4. Normalize dynamic UUIDs, timestamps, long numbers, probe paths, HTML tags, scripts, and styles.
5. Compare body text, response length, title, status, and redirect destination as a weighted fingerprint.
6. Filter a candidate only when its baseline is stable and its score reaches the configured threshold.

This preserves directory-specific error-page detection while reducing baseline requests from five per
scope to one request for scopes that behave like the root, or three requests for distinct scopes.

## Installation

The project is not installed as a package. Dependencies are listed in
`requirements.txt` and the scanner is started through the `wps.py` entry file.

```bash
git clone https://github.com/kaixliu56/wpsscanner.git
cd wpsscanner
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

For development:

```bash
pip install -r requirements-dev.txt
pytest
ruff check .
```

## Usage

```bash
python wps.py -u https://example.com -w paths.txt
```

Useful options:

```bash
python wps.py \
  -u https://example.com \
  -w paths.txt \
  -t 20 \
  --rate 30 \
  --status 200-299,301,302,401,403 \
  -H 'Authorization: Bearer TOKEN' \
  --cookie 'session=VALUE' \
  --proxy http://127.0.0.1:8080 \
  --format jsonl \
  -o results.jsonl
```

Additional modes:

```bash
# Multiple targets
python wps.py -l targets.txt -w paths.txt

# One recursion level
python wps.py -u https://example.com -w paths.txt --recursion

# Follow redirects or ignore TLS certificate errors explicitly
python wps.py -u https://example.com -w paths.txt --follow-redirects --insecure

# Tune soft-404 detection
python wps.py -u https://example.com -w paths.txt \
  --baseline-samples 3 \
  --baseline-consistency 0.72 \
  --soft404-threshold 0.82 \
  --debug
```

By default redirects are not followed, TLS certificates are verified, response bodies are capped at
256 KiB, and these statuses are retained:

```text
200-299,301,302,307,308,401,403,405
```

## Output

Text output contains status, captured body length, URL, optional redirect destination, and title.
JSONL output produces one `ScanResult` object per line for later processing.
