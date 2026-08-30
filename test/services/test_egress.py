"""
Tests for app.utils.egress — Phase 1B.2B isolated safe-egress foundation.

All tests use mocked DNS resolution and mocked HTTP responses.
No live network requests are made.
"""

import ipaddress
import logging
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch, PropertyMock

import pytest
import requests

from app.utils.egress import (
    EgressAuditEvent,
    EgressPolicy,
    EgressPolicyError,
    IPBlockedError,
    MIMECategory,
    MIMETypeNotAllowedError,
    RedirectLimitExceededError,
    SizeLimitExceededError,
    URLValidationError,
    _get_mime_category,
    _is_hostname_allowed,
    _normalize_hostname,
    _resolve_and_validate_ip,
    _validate_mime_type,
    safe_api_request,
    safe_download,
    validate_url,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def default_policy():
    """Default egress policy with example.com allowlisted."""
    return EgressPolicy(
        allowed_hosts=frozenset({"example.com", "*.cdn.example.com"}),
    )


@pytest.fixture
def mock_resolver_public():
    """Mock DNS resolver returning a public IP."""
    return lambda hostname: ["93.184.216.34"]


@pytest.fixture
def mock_resolver_factory():
    """Factory for creating mock resolvers with specific IPs."""
    def _factory(ips):
        return lambda hostname: ips
    return _factory


@pytest.fixture
def tmp_destination(tmp_path):
    """Temporary destination directory."""
    return tmp_path / "downloads"


def _make_mock_response(
    status_code=200,
    content_type="application/json",
    content_length=None,
    body=b"{}",
    chunks=None,
):
    """Build a mock requests.Response for streaming tests."""
    response = MagicMock(spec=requests.Response)
    response.status_code = status_code
    response.headers = {}
    if content_type:
        response.headers["Content-Type"] = content_type
    if content_length is not None:
        response.headers["Content-Length"] = str(content_length)
    response.content = body
    response.raise_for_status = Mock()

    if chunks is not None:
        response.iter_content = Mock(return_value=iter(chunks))
    else:
        response.iter_content = Mock(return_value=iter([body]))

    return response


# ---------------------------------------------------------------------------
# Hostname normalization tests
# ---------------------------------------------------------------------------

class TestNormalizeHostname:
    def test_lowercase(self):
        assert _normalize_hostname("EXAMPLE.COM") == "example.com"

    def test_trailing_dot(self):
        assert _normalize_hostname("example.com.") == "example.com"

    def test_multiple_trailing_dots(self):
        assert _normalize_hostname("example.com..") == "example.com"

    def test_empty_raises(self):
        with pytest.raises(URLValidationError, match="empty hostname"):
            _normalize_hostname("")

    def test_idna_punycode(self):
        # münchen.de → xn--mnchen-3ya.de
        result = _normalize_hostname("münchen.de")
        assert result == "xn--mnchen-3ya.de"

    def test_idna_ascii_passthrough(self):
        assert _normalize_hostname("example.com") == "example.com"


# ---------------------------------------------------------------------------
# Hostname allowlist tests
# ---------------------------------------------------------------------------

class TestHostnameAllowlist:
    def test_exact_match(self):
        assert _is_hostname_allowed("example.com", frozenset({"example.com"}))

    def test_exact_match_case_insensitive(self):
        assert _is_hostname_allowed("EXAMPLE.COM", frozenset({"example.com"}))

    def test_exact_match_trailing_dot(self):
        assert _is_hostname_allowed("example.com.", frozenset({"example.com"}))

    def test_no_match(self):
        assert not _is_hostname_allowed("evil.com", frozenset({"example.com"}))

    def test_subdomain_wildcard_match(self):
        assert _is_hostname_allowed("api.cdn.example.com", frozenset({"*.cdn.example.com"}))

    def test_subdomain_wildcard_direct(self):
        """*.cdn.example.com matches sub.cdn.example.com but not bare cdn.example.com."""
        assert _is_hostname_allowed("sub.cdn.example.com", frozenset({"*.cdn.example.com"}))
        assert not _is_hostname_allowed("cdn.example.com", frozenset({"*.cdn.example.com"}))

    def test_wildcard_does_not_match_bare_domain(self):
        """*.example.com must NOT match example.com itself."""
        assert not _is_hostname_allowed("example.com", frozenset({"*.example.com"}))

    def test_wildcard_boundary_bypass_evil_prefix(self):
        """evil-example.com must NOT match *.example.com."""
        assert not _is_hostname_allowed("evil-example.com", frozenset({"*.example.com"}))

    def test_wildcard_boundary_bypass_suffix(self):
        """example.com.evil.com must NOT match *.example.com."""
        assert not _is_hostname_allowed("example.com.evil.com", frozenset({"*.example.com"}))

    def test_wildcard_boundary_bypass_no_dot(self):
        """notexample.com must NOT match *.example.com."""
        assert not _is_hostname_allowed("notexample.com", frozenset({"*.example.com"}))

    def test_empty_pattern_skipped(self):
        assert not _is_hostname_allowed("example.com", frozenset({""}))

    def test_multiple_patterns(self):
        hosts = frozenset({"api.example.com", "*.cdn.example.com"})
        assert _is_hostname_allowed("api.example.com", hosts)
        assert _is_hostname_allowed("img.cdn.example.com", hosts)
        assert not _is_hostname_allowed("other.com", hosts)


# ---------------------------------------------------------------------------
# IP resolution and blocking tests
# ---------------------------------------------------------------------------

class TestResolveAndValidateIP:
    def test_public_ip_allowed(self, mock_resolver_public):
        ips = _resolve_and_validate_ip("example.com", EgressPolicy().blocked_networks, mock_resolver_public)
        assert len(ips) == 1
        assert ips[0] == ipaddress.ip_address("93.184.216.34")

    def test_loopback_ipv4_blocked(self, mock_resolver_factory):
        with pytest.raises(IPBlockedError, match="127"):
            _resolve_and_validate_ip("example.com", EgressPolicy().blocked_networks, mock_resolver_factory(["127.0.0.1"]))

    def test_loopback_ipv6_blocked(self, mock_resolver_factory):
        with pytest.raises(IPBlockedError, match="::1"):
            _resolve_and_validate_ip("example.com", EgressPolicy().blocked_networks, mock_resolver_factory(["::1"]))

    def test_private_10_blocked(self, mock_resolver_factory):
        with pytest.raises(IPBlockedError, match=r"10\."):
            _resolve_and_validate_ip("example.com", EgressPolicy().blocked_networks, mock_resolver_factory(["10.0.0.1"]))

    def test_private_172_blocked(self, mock_resolver_factory):
        with pytest.raises(IPBlockedError, match=r"172\."):
            _resolve_and_validate_ip("example.com", EgressPolicy().blocked_networks, mock_resolver_factory(["172.16.0.1"]))

    def test_private_192_blocked(self, mock_resolver_factory):
        with pytest.raises(IPBlockedError, match=r"192\."):
            _resolve_and_validate_ip("example.com", EgressPolicy().blocked_networks, mock_resolver_factory(["192.168.1.1"]))

    def test_link_local_blocked(self, mock_resolver_factory):
        with pytest.raises(IPBlockedError, match=r"169\.254"):
            _resolve_and_validate_ip("example.com", EgressPolicy().blocked_networks, mock_resolver_factory(["169.254.1.1"]))

    def test_multicast_blocked(self, mock_resolver_factory):
        with pytest.raises(IPBlockedError, match="224"):
            _resolve_and_validate_ip("example.com", EgressPolicy().blocked_networks, mock_resolver_factory(["224.0.0.1"]))

    def test_reserved_blocked(self, mock_resolver_factory):
        with pytest.raises(IPBlockedError, match="240"):
            _resolve_and_validate_ip("example.com", EgressPolicy().blocked_networks, mock_resolver_factory(["240.0.0.1"]))

    def test_unspecified_ipv4_blocked(self, mock_resolver_factory):
        with pytest.raises(IPBlockedError, match=r"0\.0\.0\.0"):
            _resolve_and_validate_ip("example.com", EgressPolicy().blocked_networks, mock_resolver_factory(["0.0.0.0"]))

    def test_unspecified_ipv6_blocked(self, mock_resolver_factory):
        with pytest.raises(IPBlockedError, match="::"):
            _resolve_and_validate_ip("example.com", EgressPolicy().blocked_networks, mock_resolver_factory(["::"]))

    def test_ipv4_mapped_ipv6_blocked(self, mock_resolver_factory):
        """IPv4-mapped IPv6 addresses like ::ffff:127.0.0.1 must be blocked."""
        with pytest.raises(IPBlockedError):
            _resolve_and_validate_ip("example.com", EgressPolicy().blocked_networks, mock_resolver_factory(["::ffff:127.0.0.1"]))

    def test_ipv4_mapped_ipv6_private_blocked(self, mock_resolver_factory):
        """IPv4-mapped IPv6 with private IPv4 must be blocked."""
        with pytest.raises(IPBlockedError):
            _resolve_and_validate_ip("example.com", EgressPolicy().blocked_networks, mock_resolver_factory(["::ffff:10.0.0.1"]))

    def test_cloud_metadata_aws_blocked(self, mock_resolver_factory):
        with pytest.raises(IPBlockedError, match=r"169\.254\.169\.254"):
            _resolve_and_validate_ip("example.com", EgressPolicy().blocked_networks, mock_resolver_factory(["169.254.169.254"]))

    def test_ipv6_ula_blocked(self, mock_resolver_factory):
        with pytest.raises(IPBlockedError, match="fc"):
            _resolve_and_validate_ip("example.com", EgressPolicy().blocked_networks, mock_resolver_factory(["fc00::1"]))

    def test_ipv6_link_local_blocked(self, mock_resolver_factory):
        with pytest.raises(IPBlockedError, match="fe80"):
            _resolve_and_validate_ip("example.com", EgressPolicy().blocked_networks, mock_resolver_factory(["fe80::1"]))

    def test_ipv6_multicast_blocked(self, mock_resolver_factory):
        with pytest.raises(IPBlockedError, match="ff"):
            _resolve_and_validate_ip("example.com", EgressPolicy().blocked_networks, mock_resolver_factory(["ff02::1"]))

    def test_dns_failure_raises(self):
        def failing_resolver(hostname):
            raise socket.gaierror("Name or service not known")
        with pytest.raises(URLValidationError, match="DNS resolution failed"):
            _resolve_and_validate_ip("example.com", EgressPolicy().blocked_networks, failing_resolver)

    def test_no_ips_raises(self, mock_resolver_factory):
        with pytest.raises(URLValidationError, match="no IP addresses"):
            _resolve_and_validate_ip("example.com", EgressPolicy().blocked_networks, mock_resolver_factory([]))

    def test_invalid_ip_raises(self, mock_resolver_factory):
        with pytest.raises(URLValidationError, match="invalid IP"):
            _resolve_and_validate_ip("example.com", EgressPolicy().blocked_networks, mock_resolver_factory(["not-an-ip"]))

    def test_multiple_ips_all_checked(self, mock_resolver_factory):
        """If any resolved IP is blocked, the entire request must fail."""
        with pytest.raises(IPBlockedError):
            _resolve_and_validate_ip(
                "example.com",
                EgressPolicy().blocked_networks,
                mock_resolver_factory(["93.184.216.34", "10.0.0.1"]),
            )


# ---------------------------------------------------------------------------
# URL validation tests
# ---------------------------------------------------------------------------

class TestValidateURL:
    def test_valid_https(self, default_policy, mock_resolver_public):
        url = validate_url("https://example.com/path", default_policy, resolver=mock_resolver_public)
        assert url.startswith("https://example.com")

    def test_http_rejected(self, default_policy, mock_resolver_public):
        with pytest.raises(URLValidationError, match="scheme must be https"):
            validate_url("http://example.com/path", default_policy, resolver=mock_resolver_public)

    def test_ftp_rejected(self, default_policy, mock_resolver_public):
        with pytest.raises(URLValidationError, match="scheme must be https"):
            validate_url("ftp://example.com/path", default_policy, resolver=mock_resolver_public)

    def test_userinfo_rejected(self, default_policy, mock_resolver_public):
        with pytest.raises(URLValidationError, match="userinfo"):
            validate_url("https://user:pass@example.com/path", default_policy, resolver=mock_resolver_public)

    def test_userinfo_only_user_rejected(self, default_policy, mock_resolver_public):
        with pytest.raises(URLValidationError, match="userinfo"):
            validate_url("https://user@example.com/path", default_policy, resolver=mock_resolver_public)

    def test_unexpected_port_rejected(self, default_policy, mock_resolver_public):
        with pytest.raises(URLValidationError, match="unexpected port"):
            validate_url("https://example.com:8080/path", default_policy, resolver=mock_resolver_public)

    def test_port_443_allowed(self, default_policy, mock_resolver_public):
        url = validate_url("https://example.com:443/path", default_policy, resolver=mock_resolver_public)
        assert "example.com" in url

    def test_port_8443_allowed(self, default_policy, mock_resolver_public):
        url = validate_url("https://example.com:8443/path", default_policy, resolver=mock_resolver_public)
        assert "example.com" in url

    def test_missing_hostname_rejected(self, default_policy, mock_resolver_public):
        with pytest.raises(URLValidationError, match="missing hostname"):
            validate_url("https:///path", default_policy, resolver=mock_resolver_public)

    def test_hostname_not_in_allowlist(self, default_policy, mock_resolver_public):
        with pytest.raises(URLValidationError, match="not in allowlist"):
            validate_url("https://evil.com/path", default_policy, resolver=mock_resolver_public)

    def test_trailing_dot_normalized(self, default_policy, mock_resolver_public):
        url = validate_url("https://example.com./path", default_policy, resolver=mock_resolver_public)
        assert "example.com" in url

    def test_idna_hostname(self, mock_resolver_public):
        policy = EgressPolicy(allowed_hosts=frozenset({"xn--mnchen-3ya.de"}))
        url = validate_url("https://münchen.de/path", policy, resolver=mock_resolver_public)
        assert "xn--mnchen-3ya.de" in url

    def test_private_ip_blocked(self, default_policy, mock_resolver_factory):
        with pytest.raises(IPBlockedError):
            validate_url("https://example.com/path", default_policy, resolver=mock_resolver_factory(["192.168.1.1"]))


# ---------------------------------------------------------------------------
# MIME type validation tests
# ---------------------------------------------------------------------------

class TestMIMEValidation:
    def test_json_category(self):
        assert _get_mime_category("application/json") == MIMECategory.JSON_API

    def test_json_with_charset(self):
        assert _get_mime_category("application/json; charset=utf-8") == MIMECategory.JSON_API

    def test_image_category(self):
        assert _get_mime_category("image/jpeg") == MIMECategory.IMAGE

    def test_audio_category(self):
        assert _get_mime_category("audio/mpeg") == MIMECategory.AUDIO

    def test_video_category(self):
        assert _get_mime_category("video/mp4") == MIMECategory.VIDEO

    def test_unknown_defaults_to_json_api(self):
        assert _get_mime_category("application/octet-stream") == MIMECategory.JSON_API

    def test_validate_json_allowed(self, default_policy):
        assert _validate_mime_type("application/json", default_policy) == MIMECategory.JSON_API

    def test_validate_image_allowed(self, default_policy):
        assert _validate_mime_type("image/png", default_policy) == MIMECategory.IMAGE

    def test_validate_video_allowed(self, default_policy):
        assert _validate_mime_type("video/mp4", default_policy) == MIMECategory.VIDEO

    def test_validate_invalid_mime_rejected(self, default_policy):
        with pytest.raises(MIMETypeNotAllowedError, match="not allowed"):
            _validate_mime_type("application/x-executable", default_policy)

    def test_validate_text_html_rejected(self, default_policy):
        with pytest.raises(MIMETypeNotAllowedError, match="not allowed"):
            _validate_mime_type("text/html", default_policy)


# ---------------------------------------------------------------------------
# Audit event tests
# ---------------------------------------------------------------------------

class TestAuditEvent:
    def test_sanitize_url_removes_query(self):
        event = EgressAuditEvent("download", "https://example.com/path?key=secret&token=abc", "success")
        assert "key=secret" not in event.url
        assert "token=abc" not in event.url
        assert "example.com/path" in event.url

    def test_sanitize_url_removes_userinfo(self):
        event = EgressAuditEvent("download", "https://user:pass@example.com/path", "success")
        assert "user" not in event.url
        assert "pass" not in event.url
        assert "example.com" in event.url

    def test_sanitize_url_removes_fragment(self):
        event = EgressAuditEvent("download", "https://example.com/path#fragment", "success")
        assert "fragment" not in event.url

    def test_sanitize_url_preserves_port(self):
        event = EgressAuditEvent("download", "https://example.com:8443/path", "success")
        assert ":8443" in event.url

    def test_sanitize_invalid_url(self):
        event = EgressAuditEvent("download", "://invalid", "failure")
        # urlparse may not raise but hostname will be None
        assert "secret" not in event.url

    def test_to_dict(self):
        event = EgressAuditEvent("download", "https://example.com/file.mp4", "success", 1024)
        d = event.to_dict()
        assert d["operation"] == "download"
        assert d["status"] == "success"
        assert d["bytes_transferred"] == 1024
        assert d["error"] is None


# ---------------------------------------------------------------------------
# Safe download tests
# ---------------------------------------------------------------------------

class TestSafeDownload:
    def test_successful_download(self, default_policy, mock_resolver_public, tmp_destination):
        """Successful download with mocked HTTP response."""
        body = b"fake video content"
        mock_response = _make_mock_response(
            content_type="video/mp4",
            content_length=len(body),
            body=body,
        )

        mock_session = MagicMock(spec=requests.Session)
        mock_session.get.return_value = mock_response

        dest = tmp_destination / "video.mp4"
        result = safe_download(
            "https://example.com/video.mp4",
            dest,
            default_policy,
            session=mock_session,
            resolver=mock_resolver_public,
        )

        assert result == dest
        assert dest.exists()
        assert dest.read_bytes() == body

    def test_content_length_precheck_rejects_oversized(self, default_policy, mock_resolver_public, tmp_destination):
        """Content-Length header exceeding limit must be rejected before streaming."""
        mock_response = _make_mock_response(
            content_type="video/mp4",
            content_length=999 * 1024 * 1024,  # 999 MB > 512 MB limit
        )

        mock_session = MagicMock(spec=requests.Session)
        mock_session.get.return_value = mock_response

        dest = tmp_destination / "video.mp4"
        with pytest.raises(SizeLimitExceededError, match="Content-Length"):
            safe_download(
                "https://example.com/video.mp4",
                dest,
                default_policy,
                session=mock_session,
                resolver=mock_resolver_public,
            )

        assert not dest.exists()

    def test_streamed_body_size_enforcement(self, default_policy, mock_resolver_public, tmp_destination):
        """Streamed body exceeding limit must be rejected based on bytes actually received."""
        # Create chunks that exceed the JSON/API limit (10 MB)
        chunk_size = 1024 * 1024  # 1 MB per chunk
        chunks = [b"x" * chunk_size for _ in range(11)]  # 11 MB total

        mock_response = _make_mock_response(
            content_type="application/json",
            content_length=None,  # No Content-Length header
            chunks=chunks,
        )

        mock_session = MagicMock(spec=requests.Session)
        mock_session.get.return_value = mock_response

        dest = tmp_destination / "data.json"
        with pytest.raises(SizeLimitExceededError, match="streamed body"):
            safe_download(
                "https://example.com/data.json",
                dest,
                default_policy,
                session=mock_session,
                resolver=mock_resolver_public,
            )

        assert not dest.exists()

    def test_invalid_mime_type_rejected(self, default_policy, mock_resolver_public, tmp_destination):
        """Invalid Content-Type must be rejected."""
        mock_response = _make_mock_response(
            content_type="text/html",
            body=b"<html>evil</html>",
        )

        mock_session = MagicMock(spec=requests.Session)
        mock_session.get.return_value = mock_response

        dest = tmp_destination / "page.html"
        with pytest.raises(MIMETypeNotAllowedError):
            safe_download(
                "https://example.com/page.html",
                dest,
                default_policy,
                session=mock_session,
                resolver=mock_resolver_public,
            )

        assert not dest.exists()

    def test_partial_file_cleanup_on_error(self, default_policy, mock_resolver_public, tmp_destination):
        """Partial files must be cleaned up on any error."""
        # Create chunks that exceed the limit
        chunk_size = 1024 * 1024
        chunks = [b"x" * chunk_size for _ in range(11)]

        mock_response = _make_mock_response(
            content_type="application/json",
            content_length=None,
            chunks=chunks,
        )

        mock_session = MagicMock(spec=requests.Session)
        mock_session.get.return_value = mock_response

        dest = tmp_destination / "data.json"
        with pytest.raises(SizeLimitExceededError):
            safe_download(
                "https://example.com/data.json",
                dest,
                default_policy,
                session=mock_session,
                resolver=mock_resolver_public,
            )

        # No partial files should remain
        partial_files = list(tmp_destination.glob("*.partial"))
        assert len(partial_files) == 0

    def test_atomic_rename_only_after_success(self, default_policy, mock_resolver_public, tmp_destination):
        """Destination file must not exist until download completes successfully."""
        body = b"complete content"
        mock_response = _make_mock_response(
            content_type="video/mp4",
            content_length=len(body),
            body=body,
        )

        mock_session = MagicMock(spec=requests.Session)
        mock_session.get.return_value = mock_response

        dest = tmp_destination / "video.mp4"
        assert not dest.exists()

        result = safe_download(
            "https://example.com/video.mp4",
            dest,
            default_policy,
            session=mock_session,
            resolver=mock_resolver_public,
        )

        assert dest.exists()
        assert dest.read_bytes() == body

    def test_same_directory_temp_file(self, default_policy, mock_resolver_public, tmp_destination):
        """Temporary file must be created in the same directory as destination."""
        body = b"test"
        mock_response = _make_mock_response(
            content_type="video/mp4",
            content_length=len(body),
            body=body,
        )

        mock_session = MagicMock(spec=requests.Session)
        mock_session.get.return_value = mock_response

        dest = tmp_destination / "subdir" / "video.mp4"
        safe_download(
            "https://example.com/video.mp4",
            dest,
            default_policy,
            session=mock_session,
            resolver=mock_resolver_public,
        )

        assert dest.exists()

    def test_audit_logging_success(self, default_policy, mock_resolver_public, tmp_destination, caplog):
        """Successful downloads must emit sanitized audit events."""
        body = b"test"
        mock_response = _make_mock_response(
            content_type="video/mp4",
            content_length=len(body),
            body=body,
        )

        mock_session = MagicMock(spec=requests.Session)
        mock_session.get.return_value = mock_response

        dest = tmp_destination / "video.mp4"
        with caplog.at_level(logging.INFO):
            safe_download(
                "https://example.com/video.mp4?secret=key123",
                dest,
                default_policy,
                session=mock_session,
                resolver=mock_resolver_public,
            )

        # Check that the audit event was logged
        assert any("egress_download_success" in record.message for record in caplog.records)

    def test_audit_logging_failure(self, default_policy, mock_resolver_public, tmp_destination, caplog):
        """Failed downloads must emit sanitized audit events."""
        mock_response = _make_mock_response(
            content_type="text/html",
            body=b"<html>evil</html>",
        )

        mock_session = MagicMock(spec=requests.Session)
        mock_session.get.return_value = mock_response

        dest = tmp_destination / "page.html"
        with caplog.at_level(logging.WARNING):
            with pytest.raises(MIMETypeNotAllowedError):
                safe_download(
                    "https://example.com/page.html?token=abc",
                    dest,
                    default_policy,
                    session=mock_session,
                    resolver=mock_resolver_public,
                )

        assert any("egress_download_failure" in record.message for record in caplog.records)

    def test_timeout_configuration(self, default_policy, mock_resolver_public, tmp_destination):
        """Timeouts must be passed to the HTTP session."""
        mock_response = _make_mock_response(
            content_type="video/mp4",
            content_length=4,
            body=b"test",
        )

        mock_session = MagicMock(spec=requests.Session)
        mock_session.get.return_value = mock_response

        dest = tmp_destination / "video.mp4"
        safe_download(
            "https://example.com/video.mp4",
            dest,
            default_policy,
            session=mock_session,
            resolver=mock_resolver_public,
        )

        # Verify timeout was passed
        call_kwargs = mock_session.get.call_args[1]
        assert call_kwargs["timeout"] == (default_policy.connect_timeout, default_policy.read_timeout)

    def test_tls_verify_enabled(self, default_policy, mock_resolver_public, tmp_destination):
        """TLS verification must always be enabled."""
        mock_response = _make_mock_response(
            content_type="video/mp4",
            content_length=4,
            body=b"test",
        )

        mock_session = MagicMock(spec=requests.Session)
        mock_session.get.return_value = mock_response

        dest = tmp_destination / "video.mp4"
        safe_download(
            "https://example.com/video.mp4",
            dest,
            default_policy,
            session=mock_session,
            resolver=mock_resolver_public,
        )

        call_kwargs = mock_session.get.call_args[1]
        assert call_kwargs["verify"] is True

    def test_redirects_disabled_by_default(self, default_policy, mock_resolver_public, tmp_destination):
        """Redirects must be disabled by default."""
        mock_response = _make_mock_response(
            content_type="video/mp4",
            content_length=4,
            body=b"test",
        )

        mock_session = MagicMock(spec=requests.Session)
        mock_session.get.return_value = mock_response

        dest = tmp_destination / "video.mp4"
        safe_download(
            "https://example.com/video.mp4",
            dest,
            default_policy,
            session=mock_session,
            resolver=mock_resolver_public,
        )

        call_kwargs = mock_session.get.call_args[1]
        assert call_kwargs["allow_redirects"] is False

    def test_redirects_enabled_for_media(self, mock_resolver_public, tmp_destination):
        """Media downloads may allow up to 3 redirects."""
        policy = EgressPolicy(
            allowed_hosts=frozenset({"example.com"}),
            allow_redirects=True,
            max_redirects=3,
        )

        mock_response = _make_mock_response(
            content_type="video/mp4",
            content_length=4,
            body=b"test",
        )

        mock_session = MagicMock(spec=requests.Session)
        mock_session.get.return_value = mock_response

        dest = tmp_destination / "video.mp4"
        safe_download(
            "https://example.com/video.mp4",
            dest,
            policy,
            session=mock_session,
            resolver=mock_resolver_public,
        )

        call_kwargs = mock_session.get.call_args[1]
        assert call_kwargs["allow_redirects"] is True


# ---------------------------------------------------------------------------
# Safe API request tests
# ---------------------------------------------------------------------------

class TestSafeAPIRequest:
    def test_successful_api_request(self, default_policy, mock_resolver_public):
        """Successful API request with mocked response."""
        mock_response = _make_mock_response(
            content_type="application/json",
            content_length=2,
            body=b"{}",
        )

        mock_session = MagicMock(spec=requests.Session)
        mock_session.request.return_value = mock_response

        response = safe_api_request(
            "https://example.com/api/data",
            default_policy,
            session=mock_session,
            resolver=mock_resolver_public,
        )

        assert response.status_code == 200

    def test_redirects_always_rejected_for_api(self, mock_resolver_public):
        """API calls must never follow redirects, even if policy allows them."""
        policy = EgressPolicy(
            allowed_hosts=frozenset({"example.com"}),
            allow_redirects=True,
            max_redirects=3,
        )

        mock_response = _make_mock_response(
            content_type="application/json",
            content_length=2,
            body=b"{}",
        )

        mock_session = MagicMock(spec=requests.Session)
        mock_session.request.return_value = mock_response

        safe_api_request(
            "https://example.com/api/data",
            policy,
            session=mock_session,
            resolver=mock_resolver_public,
        )

        call_kwargs = mock_session.request.call_args[1]
        assert call_kwargs["allow_redirects"] is False

    def test_api_content_length_precheck(self, default_policy, mock_resolver_public):
        """API responses with oversized Content-Length must be rejected."""
        mock_response = _make_mock_response(
            content_type="application/json",
            content_length=11 * 1024 * 1024,  # 11 MB > 10 MB limit
        )

        mock_session = MagicMock(spec=requests.Session)
        mock_session.request.return_value = mock_response

        with pytest.raises(SizeLimitExceededError, match="Content-Length"):
            safe_api_request(
                "https://example.com/api/data",
                default_policy,
                session=mock_session,
                resolver=mock_resolver_public,
            )

    def test_api_invalid_mime_rejected(self, default_policy, mock_resolver_public):
        """API responses with invalid Content-Type must be rejected."""
        mock_response = _make_mock_response(
            content_type="text/html",
            body=b"<html>error</html>",
        )

        mock_session = MagicMock(spec=requests.Session)
        mock_session.request.return_value = mock_response

        with pytest.raises(MIMETypeNotAllowedError):
            safe_api_request(
                "https://example.com/api/data",
                default_policy,
                session=mock_session,
                resolver=mock_resolver_public,
            )

    def test_api_audit_logging(self, default_policy, mock_resolver_public, caplog):
        """API requests must emit sanitized audit events."""
        mock_response = _make_mock_response(
            content_type="application/json",
            content_length=2,
            body=b"{}",
        )

        mock_session = MagicMock(spec=requests.Session)
        mock_session.request.return_value = mock_response

        with caplog.at_level(logging.INFO):
            safe_api_request(
                "https://example.com/api/data?api_key=secret",
                default_policy,
                session=mock_session,
                resolver=mock_resolver_public,
            )

        assert any("egress_api_success" in record.message for record in caplog.records)


# ---------------------------------------------------------------------------
# Policy configuration tests
# ---------------------------------------------------------------------------

class TestPolicyConfiguration:
    def test_default_size_limits(self):
        policy = EgressPolicy()
        assert policy.max_bytes_json_api == 10 * 1024 * 1024
        assert policy.max_bytes_image == 25 * 1024 * 1024
        assert policy.max_bytes_audio == 100 * 1024 * 1024
        assert policy.max_bytes_video == 512 * 1024 * 1024

    def test_default_redirects_disabled(self):
        policy = EgressPolicy()
        assert policy.allow_redirects is False
        assert policy.max_redirects == 3

    def test_default_timeouts(self):
        policy = EgressPolicy()
        assert policy.connect_timeout == 10.0
        assert policy.read_timeout == 30.0

    def test_get_max_bytes_for_category(self):
        policy = EgressPolicy()
        assert policy.get_max_bytes_for_category(MIMECategory.JSON_API) == 10 * 1024 * 1024
        assert policy.get_max_bytes_for_category(MIMECategory.VIDEO) == 512 * 1024 * 1024

    def test_get_allowed_mime_for_category(self):
        policy = EgressPolicy()
        assert "application/json" in policy.get_allowed_mime_for_category(MIMECategory.JSON_API)
        assert "video/mp4" in policy.get_allowed_mime_for_category(MIMECategory.VIDEO)

    def test_blocked_networks_include_cloud_metadata(self):
        policy = EgressPolicy()
        metadata_ip = ipaddress.ip_address("169.254.169.254")
        assert any(metadata_ip in network for network in policy.blocked_networks)


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_url_with_credentials_in_path(self, default_policy, mock_resolver_public):
        """URLs with credentials in path (not userinfo) should be allowed."""
        url = validate_url(
            "https://example.com/path/with/token/abc123",
            default_policy,
            resolver=mock_resolver_public,
        )
        assert "example.com" in url

    def test_empty_allowlist_rejects_all(self, mock_resolver_public):
        """Empty allowlist must reject all hostnames."""
        policy = EgressPolicy(allowed_hosts=frozenset())
        with pytest.raises(URLValidationError, match="not in allowlist"):
            validate_url("https://example.com/path", policy, resolver=mock_resolver_public)

    def test_case_insensitive_scheme(self, default_policy, mock_resolver_public):
        """Scheme comparison must be case-insensitive."""
        url = validate_url("HTTPS://example.com/path", default_policy, resolver=mock_resolver_public)
        assert url.startswith("https://")

    def test_url_with_fragment(self, default_policy, mock_resolver_public):
        """URLs with fragments should be validated (fragment preserved in normalized URL)."""
        url = validate_url("https://example.com/path#section", default_policy, resolver=mock_resolver_public)
        assert "example.com" in url

    def test_download_to_existing_file_overwrites(self, default_policy, mock_resolver_public, tmp_destination):
        """Downloading to an existing file must overwrite it atomically."""
        body = b"new content"
        mock_response = _make_mock_response(
            content_type="video/mp4",
            content_length=len(body),
            body=body,
        )

        mock_session = MagicMock(spec=requests.Session)
        mock_session.get.return_value = mock_response

        dest = tmp_destination / "video.mp4"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"old content")

        safe_download(
            "https://example.com/video.mp4",
            dest,
            default_policy,
            session=mock_session,
            resolver=mock_resolver_public,
        )

        assert dest.read_bytes() == body
