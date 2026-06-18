import json
import socket
import ipaddress
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.cookies import RequestsCookieJar
from urllib.parse import urlparse, urljoin

from config import TIMEOUT, CONNECT_TIMEOUT, HEADERS, MAX_CONTENT_LENGTH

MAX_REDIRECTS = 10

class SafeRequestException(Exception):
    pass

class SSRFDetectedException(SafeRequestException):
    pass

class SizeLimitExceededException(SafeRequestException):
    pass

class RequestTimeoutException(SafeRequestException):
    pass

class RequestConnectionException(SafeRequestException):
    pass


@dataclass
class HttpResponse:
    """Lightweight response object used by checks (supports caching)."""
    status_code: int
    headers: dict
    text: str
    url: str
    cookies: RequestsCookieJar = field(default_factory=RequestsCookieJar)

    def json(self):
        return json.loads(self.text)

    @classmethod
    def from_requests(cls, response: requests.Response) -> "HttpResponse":
        return cls(
            status_code=response.status_code,
            headers=dict(response.headers),
            text=response.text,
            url=response.url,
            cookies=response.cookies,
        )


_page_cache: dict[str, HttpResponse] = {}
_allow_localhost: bool = False


def set_allow_localhost(allow: bool) -> None:
    global _allow_localhost
    _allow_localhost = allow


def clear_request_cache() -> None:
    _page_cache.clear()


def fetch_page(url: str, *, allow_redirects: bool = True, headers: Optional[dict] = None) -> HttpResponse:
    """Cached GET for the main page — avoids duplicate fetches across checks."""
    hdrs = headers or HEADERS
    cache_key = f"{url}|{allow_redirects}|{hdrs.get('Origin', '')}"
    if cache_key in _page_cache:
        return _page_cache[cache_key]

    response = safe_request("GET", url, headers=hdrs, allow_redirects=allow_redirects)
    cached = HttpResponse.from_requests(response)
    _page_cache[cache_key] = cached
    return cached


def is_safe_hostname(hostname: str) -> str:
    """
    Validates a hostname against SSRF attacks.
    Returns the resolved IP address if safe.
    Raises SSRFDetectedException if unsafe.
    """
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        raise SSRFDetectedException(f"Could not resolve hostname: {hostname}")

    ip_obj = ipaddress.ip_address(ip)

    if ip_obj.is_loopback and _allow_localhost:
        return ip

    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast:
        raise SSRFDetectedException(f"URL resolves to a restricted internal IP: {ip}")

    if ip == "169.254.169.254":
        raise SSRFDetectedException("Cloud metadata endpoint access denied")

    return ip


def _validate_url(url: str) -> tuple[str, str]:
    """Helper to parse and validate URL for SSRF. Returns (hostname, safe_ip)."""
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        raise SSRFDetectedException("Invalid URL: Missing hostname")

    safe_ip = is_safe_hostname(hostname)
    return hostname, safe_ip


def _read_body(response: requests.Response) -> requests.Response:
    """Stream-read the response body with a hard size cap."""
    content_length = response.headers.get("Content-Length")
    if content_length:
        try:
            if int(content_length) > MAX_CONTENT_LENGTH:
                response.close()
                raise SizeLimitExceededException(
                    f"Response exceeds maximum size limit of {MAX_CONTENT_LENGTH} bytes"
                )
        except ValueError:
            pass

    chunks = []
    total = 0
    for chunk in response.iter_content(chunk_size=8192):
        total += len(chunk)
        if total > MAX_CONTENT_LENGTH:
            response.close()
            raise SizeLimitExceededException(
                f"Response exceeds maximum size limit of {MAX_CONTENT_LENGTH} bytes"
            )
        chunks.append(chunk)

    response._content = b"".join(chunks)
    return response


def _request_with_pinned_dns(
    method: str,
    url: str,
    hostname: str,
    safe_ip: str,
    **kwargs,
) -> requests.Response:
    """
    Pin DNS resolution to safe_ip while keeping the original hostname in the URL.
    Preserves TLS SNI/certificate validation and keeps URLs compatible with test mocks.
    """
    real_getaddrinfo = socket.getaddrinfo

    def _patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        if host == hostname:
            host = safe_ip
        return real_getaddrinfo(host, port, family, type, proto, flags)

    socket.getaddrinfo = _patched_getaddrinfo
    try:
        return requests.request(method, url, allow_redirects=False, **kwargs)
    finally:
        socket.getaddrinfo = real_getaddrinfo


def safe_request(method: str, url: str, **kwargs) -> requests.Response:
    """
    A safe wrapper around requests that:
    - Validates every hostname (initial + each redirect hop) against SSRF filters
    - Pins DNS to the validated IP to prevent rebinding between check and connect
    - Streams responses with a hard size cap
    - Enforces strict connect/read timeouts
    """
    caller_wants_redirects = kwargs.pop("allow_redirects", True)
    timeout = kwargs.pop("timeout", (CONNECT_TIMEOUT, TIMEOUT))

    headers = dict(kwargs.get("headers") or HEADERS)
    if "User-Agent" not in headers:
        headers["User-Agent"] = HEADERS["User-Agent"]
    kwargs["headers"] = headers
    kwargs["stream"] = True

    try:
        current_url = url
        for _ in range(MAX_REDIRECTS + 1):
            hostname, safe_ip = _validate_url(current_url)

            response = _request_with_pinned_dns(
                method, current_url, hostname, safe_ip, timeout=timeout, **kwargs
            )

            if not caller_wants_redirects or response.status_code not in (301, 302, 303, 307, 308):
                return _read_body(response)

            location = response.headers.get("Location")
            if not location:
                return _read_body(response)

            current_url = urljoin(current_url, location)
            response.close()
            method = "GET"

        raise RequestConnectionException("Too many redirects")

    except SafeRequestException:
        raise
    except requests.exceptions.ConnectionError as e:
        raise RequestConnectionException(f"Connection error: {str(e)}")
    except requests.exceptions.Timeout:
        raise RequestTimeoutException("Request timed out")
    except requests.exceptions.SSLError as e:
        raise RequestConnectionException(f"SSL error: {str(e)}")
    except requests.exceptions.TooManyRedirects:
        raise RequestConnectionException("Too many redirects")
    except requests.exceptions.RequestException as e:
        raise RequestConnectionException(f"Request failed: {str(e)}")
