"""
Centralized URL-policy and safe-download module for BrainTrustCrypto pilot mode.

This module provides the isolated safe-egress foundation for Phase 1B.2B.
It enforces HTTPS-only, hostname allowlists, IP blocklists, size caps,
MIME allowlists, redirect controls, and sanitized audit logging.

LIMITATION: DNS validation alone has a TOCTOU/rebinding limitation.
A malicious DNS resolver could return a public IP for validation and
a private IP for the actual connection. This module must be paired with
container/firewall egress isolation for complete protection.
"""

import ipaddress
import logging
import os
import re
import shutil
import socket
import tempfile
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import BinaryIO, Callable, Iterable, Optional
from urllib.parse import urlparse, urlunparse

import requests

logger = logging.getLogger(__name__)


class EgressPolicyError(Exception):
    """Base exception for egress policy violations."""


class URLValidationError(EgressPolicyError):
    """URL failed validation."""


class IPBlockedError(EgressPolicyError):
    """Resolved IP is in a blocked range."""


class SizeLimitExceededError(EgressPolicyError):
    """Response body exceeded the configured size limit."""


class MIMETypeNotAllowedError(EgressPolicyError):
    """Response Content-Type is not in the allowlist."""


class RedirectLimitExceededError(EgressPolicyError):
    """Too many redirects or redirect to disallowed target."""


class EgressAuditEvent:
    """Sanitized audit event for egress operations."""

    def __init__(
        self,
        operation: str,
        url: str,
        status: str,
        bytes_transferred: int = 0,
        error: Optional[str] = None,
    ):
        self.operation = operation
        self.url = self._sanitize_url(url)
        self.status = status
        self.bytes_transferred = bytes_transferred
        self.error = error

    @staticmethod
    def _sanitize_url(url: str) -> str:
        """Redact query strings, userinfo, and credentials from URL."""
        try:
            parsed = urlparse(url)
            # Remove userinfo
            netloc = parsed.hostname or ""
            if parsed.port:
                netloc = f"{netloc}:{parsed.port}"
            # Rebuild without query, fragment, or userinfo
            sanitized = urlunparse(
                (parsed.scheme, netloc, parsed.path, "", "", "")
            )
            return sanitized
        except Exception:
            return "<invalid-url>"

    def to_dict(self) -> dict:
        return {
            "operation": self.operation,
            "url": self.url,
            "status": self.status,
            "bytes_transferred": self.bytes_transferred,
            "error": self.error,
        }


class MIMECategory(Enum):
    JSON_API = "json_api"
    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"


@dataclass(frozen=True)
class EgressPolicy:
    """Immutable egress policy configuration."""

    # Hostname allowlist: exact matches or boundary-safe subdomain rules
    # Example: "api.pexels.com" matches exactly; "*.pexels.com" matches subdomains
    allowed_hosts: frozenset[str] = field(default_factory=frozenset)

    # Size limits by MIME category (bytes)
    max_bytes_json_api: int = 10 * 1024 * 1024  # 10 MB
    max_bytes_image: int = 25 * 1024 * 1024  # 25 MB
    max_bytes_audio: int = 100 * 1024 * 1024  # 100 MB
    max_bytes_video: int = 512 * 1024 * 1024  # 512 MB

    # Redirect policy
    allow_redirects: bool = False
    max_redirects: int = 3  # Only used if allow_redirects=True

    # Timeouts (seconds)
    connect_timeout: float = 10.0
    read_timeout: float = 30.0

    # MIME type allowlists by category
    allowed_mime_json_api: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {"application/json", "application/json; charset=utf-8", "text/json"}
        )
    )
    allowed_mime_image: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {"image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml"}
        )
    )
    allowed_mime_audio: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {"audio/mpeg", "audio/mp3", "audio/wav", "audio/ogg", "audio/aac", "audio/flac"}
        )
    )
    allowed_mime_video: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {"video/mp4", "video/webm", "video/quicktime", "video/x-msvideo", "video/x-matroska"}
        )
    )

    # Blocked IP networks (CIDR notation)
    blocked_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = field(
        default_factory=lambda: (
            # IPv4 loopback
            ipaddress.ip_network("127.0.0.0/8"),
            # IPv4 private
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            # IPv4 link-local
            ipaddress.ip_network("169.254.0.0/16"),
            # IPv4 multicast
            ipaddress.ip_network("224.0.0.0/4"),
            # IPv4 reserved
            ipaddress.ip_network("240.0.0.0/4"),
            # IPv4 unspecified
            ipaddress.ip_network("0.0.0.0/8"),
            # IPv4 broadcast
            ipaddress.ip_network("255.255.255.255/32"),
            # IPv6 loopback
            ipaddress.ip_network("::1/128"),
            # IPv6 private (ULA)
            ipaddress.ip_network("fc00::/7"),
            # IPv6 link-local
            ipaddress.ip_network("fe80::/10"),
            # IPv6 multicast
            ipaddress.ip_network("ff00::/8"),
            # IPv6 unspecified
            ipaddress.ip_network("::/128"),
            # IPv4-mapped IPv6
            ipaddress.ip_network("::ffff:0:0/96"),
            # Cloud metadata (AWS, GCP, Azure, etc.)
            ipaddress.ip_network("169.254.169.254/32"),
            ipaddress.ip_network("fd00:ec2::254/128"),
        )
    )

    def get_max_bytes_for_category(self, category: MIMECategory) -> int:
        """Get the size limit for a MIME category."""
        return {
            MIMECategory.JSON_API: self.max_bytes_json_api,
            MIMECategory.IMAGE: self.max_bytes_image,
            MIMECategory.AUDIO: self.max_bytes_audio,
            MIMECategory.VIDEO: self.max_bytes_video,
        }[category]

    def get_allowed_mime_for_category(self, category: MIMECategory) -> frozenset[str]:
        """Get the MIME allowlist for a category."""
        return {
            MIMECategory.JSON_API: self.allowed_mime_json_api,
            MIMECategory.IMAGE: self.allowed_mime_image,
            MIMECategory.AUDIO: self.allowed_mime_audio,
            MIMECategory.VIDEO: self.allowed_mime_video,
        }[category]


def _normalize_hostname(hostname: str) -> str:
    """
    Normalize hostname: lowercase, strip trailing dot, handle IDNA.
    Returns the normalized ASCII hostname.
    """
    if not hostname:
        raise URLValidationError("empty hostname")

    # Strip trailing dot (DNS root)
    hostname = hostname.rstrip(".")

    # Convert IDNA to ASCII
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError) as exc:
        raise URLValidationError(f"invalid IDNA hostname: {exc}") from exc

    # Lowercase for comparison
    return hostname.lower()


def _is_hostname_allowed(hostname: str, allowed_hosts: frozenset[str]) -> bool:
    """
    Check if hostname matches the allowlist.
    Supports exact matches and boundary-safe subdomain rules (*.example.com).
    """
    normalized = _normalize_hostname(hostname)

    for pattern in allowed_hosts:
        pattern = pattern.lower().strip()
        if not pattern:
            continue

        if pattern.startswith("*."):
            # Boundary-safe subdomain match: *.example.com matches sub.example.com
            # but NOT example.com itself or evil-example.com
            suffix = pattern[2:]  # Remove "*."
            if normalized == suffix:
                # *.example.com does NOT match example.com
                continue
            if normalized.endswith("." + suffix):
                return True
        else:
            # Exact match
            if normalized == pattern:
                return True

    return False


def _resolve_and_validate_ip(
    hostname: str,
    blocked_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
    resolver: Optional[Callable[[str], Iterable[str]]] = None,
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """
    Resolve hostname to IP addresses and validate against blocked networks.

    LIMITATION: DNS validation alone has a TOCTOU/rebinding limitation.
    A malicious DNS resolver could return a public IP for validation and
    a private IP for the actual connection. This must be paired with
    container/firewall egress isolation for complete protection.
    """
    if resolver is None:
        resolver = _default_resolver

    try:
        ip_strings = resolver(hostname)
    except Exception as exc:
        raise URLValidationError(f"DNS resolution failed for {hostname}: {exc}") from exc

    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for ip_str in ip_strings:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            raise URLValidationError(f"invalid IP address resolved: {ip_str}")

        # Check for IPv4-mapped IPv6
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped

        # Check against blocked networks
        for network in blocked_networks:
            if ip in network:
                raise IPBlockedError(
                    f"IP {ip} is in blocked network {network} "
                    f"(hostname: {hostname})"
                )

        ips.append(ip)

    if not ips:
        raise URLValidationError(f"no IP addresses resolved for {hostname}")

    return ips


def _default_resolver(hostname: str) -> Iterable[str]:
    """Default DNS resolver using system getaddrinfo."""
    results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    return {result[4][0] for result in results}


def validate_url(
    url: str,
    policy: EgressPolicy,
    *,
    resolver: Optional[Callable[[str], Iterable[str]]] = None,
) -> str:
    """
    Validate a URL against the egress policy.
    Returns the normalized URL if valid.
    Raises URLValidationError or IPBlockedError if invalid.
    """
    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise URLValidationError(f"invalid URL: {exc}") from exc

    # Require HTTPS
    if parsed.scheme.lower() != "https":
        raise URLValidationError(f"scheme must be https, got: {parsed.scheme}")

    # Reject userinfo
    if parsed.username or parsed.password:
        raise URLValidationError("URL userinfo is not allowed")

    # Validate hostname
    hostname = parsed.hostname
    if not hostname:
        raise URLValidationError("missing hostname")

    # Check port
    if parsed.port:
        if parsed.port not in (443, 8443):
            raise URLValidationError(f"unexpected port: {parsed.port}")

    # Normalize and check hostname allowlist
    normalized_hostname = _normalize_hostname(hostname)
    if not _is_hostname_allowed(normalized_hostname, policy.allowed_hosts):
        raise URLValidationError(
            f"hostname not in allowlist: {normalized_hostname}"
        )

    # Resolve and validate IP
    _resolve_and_validate_ip(normalized_hostname, policy.blocked_networks, resolver)

    # Rebuild normalized URL (without userinfo, with normalized hostname)
    netloc = normalized_hostname
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"

    normalized_url = urlunparse(
        (parsed.scheme.lower(), netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
    )

    return normalized_url


def _get_mime_category(content_type: str) -> MIMECategory:
    """Determine MIME category from Content-Type header."""
    content_type = content_type.lower().split(";")[0].strip()

    if content_type in ("application/json", "text/json"):
        return MIMECategory.JSON_API
    if content_type.startswith("image/"):
        return MIMECategory.IMAGE
    if content_type.startswith("audio/"):
        return MIMECategory.AUDIO
    if content_type.startswith("video/"):
        return MIMECategory.VIDEO

    # Default to JSON_API for unknown types (most restrictive)
    return MIMECategory.JSON_API


def _validate_mime_type(content_type: str, policy: EgressPolicy) -> MIMECategory:
    """Validate Content-Type against allowlist. Returns the category."""
    category = _get_mime_category(content_type)
    allowed = policy.get_allowed_mime_for_category(category)

    # Normalize content_type for comparison (strip parameters)
    normalized = content_type.lower().split(";")[0].strip()

    # Check if any allowed MIME matches (with or without parameters)
    for allowed_mime in allowed:
        allowed_normalized = allowed_mime.lower().split(";")[0].strip()
        if normalized == allowed_normalized:
            return category

    raise MIMETypeNotAllowedError(
        f"Content-Type not allowed: {content_type} "
        f"(category: {category.value}, allowed: {sorted(allowed)})"
    )


def safe_download(
    url: str,
    destination: str | Path,
    policy: EgressPolicy,
    *,
    session: Optional[requests.Session] = None,
    resolver: Optional[Callable[[str], Iterable[str]]] = None,
    audit_logger: Optional[logging.Logger] = None,
) -> Path:
    """
    Safely download a URL to a destination path with full policy enforcement.

    Features:
    - HTTPS only, hostname allowlist, IP blocklist
    - Content-Length precheck
    - Streamed body-size enforcement (bytes actually received)
    - MIME/content-type allowlist
    - Same-directory temporary partial file
    - Atomic rename only after success
    - Guaranteed partial-file cleanup
    - Sanitized audit events

    Returns the final destination path.
    """
    if audit_logger is None:
        audit_logger = logger

    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)

    # Validate URL
    normalized_url = validate_url(url, policy, resolver=resolver)

    # Create session if not provided
    if session is None:
        session = requests.Session()

    # Configure session
    session.max_redirects = policy.max_redirects if policy.allow_redirects else 0

    # Track bytes received
    bytes_received = 0
    temp_path: Optional[Path] = None

    try:
        # Make request with streaming
        response = session.get(
            normalized_url,
            stream=True,
            timeout=(policy.connect_timeout, policy.read_timeout),
            allow_redirects=policy.allow_redirects,
            verify=True,  # Always verify TLS in pilot mode
        )
        response.raise_for_status()

        # Validate Content-Type
        content_type = response.headers.get("Content-Type", "")
        category = _validate_mime_type(content_type, policy)
        max_bytes = policy.get_max_bytes_for_category(category)

        # Content-Length precheck
        content_length = response.headers.get("Content-Length")
        if content_length:
            try:
                declared_size = int(content_length)
                if declared_size > max_bytes:
                    raise SizeLimitExceededError(
                        f"Content-Length {declared_size} exceeds limit {max_bytes} "
                        f"for category {category.value}"
                    )
            except ValueError:
                # Invalid Content-Length, proceed with streaming check
                pass

        # Create temporary file in same directory
        temp_fd, temp_path_str = tempfile.mkstemp(
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".partial",
        )
        temp_path = Path(temp_path_str)

        try:
            with os.fdopen(temp_fd, "wb") as temp_file:
                # Stream with size enforcement
                for chunk in response.iter_content(chunk_size=8192):
                    if not chunk:
                        continue

                    bytes_received += len(chunk)
                    if bytes_received > max_bytes:
                        raise SizeLimitExceededError(
                            f"streamed body {bytes_received} exceeds limit {max_bytes} "
                            f"for category {category.value}"
                        )

                    temp_file.write(chunk)

            # Atomic rename only after success
            shutil.move(str(temp_path), str(destination))
            temp_path = None  # Prevent cleanup

            # Audit success
            event = EgressAuditEvent(
                operation="download",
                url=normalized_url,
                status="success",
                bytes_transferred=bytes_received,
            )
            audit_logger.info("egress_download_success", extra={"egress_event": event.to_dict()})

            return destination

        except Exception:
            # Cleanup partial file on any error
            if temp_path and temp_path.exists():
                temp_path.unlink()
            raise

    except Exception as exc:
        # Audit failure
        event = EgressAuditEvent(
            operation="download",
            url=normalized_url,
            status="failure",
            bytes_transferred=bytes_received,
            error=str(exc),
        )
        audit_logger.warning("egress_download_failure", extra={"egress_event": event.to_dict()})
        raise

    finally:
        # Guaranteed cleanup
        if temp_path and temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass


def safe_api_request(
    url: str,
    policy: EgressPolicy,
    *,
    method: str = "GET",
    session: Optional[requests.Session] = None,
    resolver: Optional[Callable[[str], Iterable[str]]] = None,
    audit_logger: Optional[logging.Logger] = None,
    **kwargs,
) -> requests.Response:
    """
    Make a safe API request with policy enforcement.
    Redirects are always rejected for API calls.
    """
    if audit_logger is None:
        audit_logger = logger

    # API calls never follow redirects
    api_policy = EgressPolicy(
        allowed_hosts=policy.allowed_hosts,
        max_bytes_json_api=policy.max_bytes_json_api,
        max_bytes_image=policy.max_bytes_image,
        max_bytes_audio=policy.max_bytes_audio,
        max_bytes_video=policy.max_bytes_video,
        allow_redirects=False,
        max_redirects=0,
        connect_timeout=policy.connect_timeout,
        read_timeout=policy.read_timeout,
        allowed_mime_json_api=policy.allowed_mime_json_api,
        allowed_mime_image=policy.allowed_mime_image,
        allowed_mime_audio=policy.allowed_mime_audio,
        allowed_mime_video=policy.allowed_mime_video,
        blocked_networks=policy.blocked_networks,
    )

    # Validate URL
    normalized_url = validate_url(url, api_policy, resolver=resolver)

    # Create session if not provided
    if session is None:
        session = requests.Session()

    # Inject timeouts
    kwargs.setdefault("timeout", (api_policy.connect_timeout, api_policy.read_timeout))
    kwargs.setdefault("allow_redirects", False)
    kwargs.setdefault("verify", True)

    try:
        response = session.request(method, normalized_url, **kwargs)
        response.raise_for_status()

        # Validate Content-Type
        content_type = response.headers.get("Content-Type", "")
        _validate_mime_type(content_type, api_policy)

        # Check size (for non-streamed responses)
        content_length = response.headers.get("Content-Length")
        if content_length:
            try:
                declared_size = int(content_length)
                if declared_size > api_policy.max_bytes_json_api:
                    raise SizeLimitExceededError(
                        f"Content-Length {declared_size} exceeds limit "
                        f"{api_policy.max_bytes_json_api} for JSON/API"
                    )
            except ValueError:
                pass

        # Audit success
        event = EgressAuditEvent(
            operation="api_request",
            url=normalized_url,
            status="success",
            bytes_transferred=len(response.content) if response.content else 0,
        )
        audit_logger.info("egress_api_success", extra={"egress_event": event.to_dict()})

        return response

    except Exception as exc:
        # Audit failure
        event = EgressAuditEvent(
            operation="api_request",
            url=normalized_url,
            status="failure",
            error=str(exc),
        )
        audit_logger.warning("egress_api_failure", extra={"egress_event": event.to_dict()})
        raise
