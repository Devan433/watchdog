import socket
import ipaddress
import requests
from urllib.parse import urlparse, urljoin
from config import TIMEOUT, HEADERS, MAX_CONTENT_LENGTH

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

def is_safe_hostname(hostname: str) -> str:
    """
    Validates a hostname against SSRF attacks.
    Returns the resolved IP address if safe.
    Raises SSRFDetectedException if unsafe.
    """
    try:
        # Resolve the hostname to an IP address (Time of Check)
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        raise SSRFDetectedException(f"Could not resolve hostname: {hostname}")

    ip_obj = ipaddress.ip_address(ip)

    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast:
        raise SSRFDetectedException(f"URL resolves to a restricted internal IP: {ip}")

    # Explicit block for cloud metadata IP (AWS/GCP/Azure)
    if ip == '169.254.169.254':
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
    content_length = response.headers.get('Content-Length')
    if content_length:
        try:
            if int(content_length) > MAX_CONTENT_LENGTH:
                response.close()
                raise SizeLimitExceededException(
                    f"Response exceeds maximum size limit of {MAX_CONTENT_LENGTH} bytes"
                )
        except ValueError:
            pass  # malformed Content-Length header, proceed to streaming check

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

def safe_request(method: str, url: str, **kwargs) -> requests.Response:
    """
    A safe wrapper around requests that:
    - Validates every hostname (initial + each redirect hop) against SSRF filters
    - Prevents DNS Rebinding for HTTP by overriding the netloc with the safe IP
    - Streams responses with a hard size cap
    - Enforces strict connect/read timeouts
    """
    caller_wants_redirects = kwargs.pop('allow_redirects', True)
    timeout = kwargs.pop('timeout', (3.0, TIMEOUT))

    headers = kwargs.get('headers', HEADERS.copy())
    if 'User-Agent' not in headers:
        headers['User-Agent'] = HEADERS['User-Agent']
    kwargs['headers'] = headers
    kwargs['stream'] = True

    try:
        current_url = url
        for _ in range(MAX_REDIRECTS + 1):
            # Validate hostname resolves to a safe (non-private) IP at every hop
            hostname, safe_ip = _validate_url(current_url)

            response = requests.request(method, current_url, allow_redirects=False, timeout=timeout, **kwargs)

            if not caller_wants_redirects or response.status_code not in (301, 302, 303, 307, 308):
                return _read_body(response)

            location = response.headers.get('Location')
            if not location:
                return _read_body(response)

            current_url = urljoin(current_url, location)
            response.close()
            method = 'GET'

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
