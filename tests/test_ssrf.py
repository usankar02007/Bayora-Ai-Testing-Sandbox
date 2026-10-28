import pytest
from tinyfish_client import validate_url_against_ssrf


def test_ssrf_rejects_non_https():
    with pytest.raises(ValueError, match="Only secure HTTPS URLs are permitted"):
        validate_url_against_ssrf("http://example.com")


def test_ssrf_rejects_localhost_and_loopback():
    with pytest.raises(ValueError, match="is prohibited"):
        validate_url_against_ssrf("https://localhost/admin")

    with pytest.raises(ValueError, match="is prohibited"):
        validate_url_against_ssrf("https://127.0.0.1:8080/internal")


def test_ssrf_rejects_cloud_metadata_ip():
    with pytest.raises(ValueError, match="is within prohibited range"):
        validate_url_against_ssrf("https://169.254.169.254/latest/meta-data/")


def test_ssrf_rejects_rfc1918_private_ranges():
    with pytest.raises(ValueError, match="is within prohibited range"):
        validate_url_against_ssrf("https://192.168.1.100/status")

    with pytest.raises(ValueError, match="is within prohibited range"):
        validate_url_against_ssrf("https://10.0.0.5/api")
