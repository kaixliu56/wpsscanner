import pytest

from wpsscanner.utils import normalize_body, normalize_target, parse_headers, parse_status_codes, path_scope


def test_normalize_target_adds_scheme_and_trailing_slash():
    assert normalize_target("example.com/base") == "http://example.com/base/"


def test_normalize_target_rejects_non_http_scheme():
    with pytest.raises(ValueError):
        normalize_target("file:///etc/passwd")


def test_path_scope_uses_first_directory():
    assert path_scope("admin/login") == "admin/"
    assert path_scope("index.php") == "/"


def test_dynamic_soft404_tokens_are_normalized():
    left = "<title>Missing</title><p>/.wpsscanner-404-aaaaaaaaaaaaaaaa at 2026-01-01 10:20:30</p>"
    right = "<title>Missing</title><p>/.wpsscanner-404-bbbbbbbbbbbbbbbb at 2027-02-02 11:22:33</p>"
    assert normalize_body(left) == normalize_body(right)


def test_reflected_request_paths_are_normalized():
    left = "<p>Unknown /.wpsscanner-404-aaaaaaaaaaaaaaaa</p>"
    right = "<p>Unknown /missing</p>"
    assert normalize_body(left, request_path="/.wpsscanner-404-aaaaaaaaaaaaaaaa") == normalize_body(
        right, request_path="/missing"
    )


def test_status_parser_supports_ranges():
    assert parse_status_codes("200-202,301,403") == {200, 201, 202, 301, 403}


def test_header_parser():
    assert parse_headers(["Authorization: Bearer x", "X-Test: yes"]) == {
        "Authorization": "Bearer x", "X-Test": "yes"
    }
