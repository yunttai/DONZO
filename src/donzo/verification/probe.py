from __future__ import annotations

import errno
import hashlib
import re
import select
import socket
import ssl
import time
from dataclasses import asdict, dataclass, field
from email.message import Message
from http.client import parse_headers
from io import BytesIO
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

from donzo.auth import auth_headers_for_url
from donzo.config import ScopeConfig
from donzo.models import stable_id

SENSITIVE_HEADER_NAMES = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}
SECRET_PATTERNS = (
    re.compile(
        r"(?i)(api[_-]?key|token|secret|password|passwd|authorization)\s*[:=]\s*['\"]?[^'\"\s,}]+"
    ),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{12,}"),
)
TITLE_PATTERN = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}
CONNECT_IN_PROGRESS_ERRORS = {
    errno.EINPROGRESS,
    errno.EWOULDBLOCK,
    getattr(errno, "WSAEINPROGRESS", errno.EINPROGRESS),
    getattr(errno, "WSAEWOULDBLOCK", errno.EWOULDBLOCK),
}


class ProbeTimeoutError(TimeoutError):
    pass


@dataclass(frozen=True)
class RedirectHop:
    status_code: int
    location: str


@dataclass(frozen=True)
class ProbeResult:
    probe_id: str
    url: str
    method: str
    status_code: int | None
    final_url: str
    redirect_chain: list[RedirectHop] = field(default_factory=list)
    content_type: str = ""
    content_length: int | None = None
    title: str = ""
    body_sha256: str = ""
    body_simhash: str = ""
    response_excerpt_redacted: str = ""
    headers_redacted: dict[str, str] = field(default_factory=dict)
    matched_patterns: list[str] = field(default_factory=list)
    error_signature: str | None = None
    body_text: str = field(default="", repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["redirect_chain"] = [asdict(item) for item in self.redirect_chain]
        data.pop("body_text", None)
        return data


def probe_url(url: str, *, config: ScopeConfig, method: str = "GET") -> ProbeResult:
    probe_config = config.verification.probe
    normalized_method = method.upper()
    if not probe_config.method_allowed(normalized_method):
        return failed_probe(
            url,
            normalized_method,
            final_url=url,
            error_signature=f"method_not_allowed:{normalized_method}",
        )

    started = time.time()
    current_url = url
    redirect_chain: list[RedirectHop] = []
    error_signature: str | None = None
    response_info: tuple[int | None, Message, bytes] | None = None

    for _attempt in range(probe_config.max_redirects + 1):
        try:
            status_code, headers, body = socket_http_request(
                current_url,
                method=normalized_method,
                timeout_seconds=probe_config.timeout_seconds,
                max_body_bytes=probe_config.max_body_bytes,
                request_headers=auth_headers_for_url(current_url, config=config),
            )
            response_info = (status_code, headers, body)
            location = headers.get("Location", "")
            if (
                probe_config.follow_redirects
                and status_code in REDIRECT_STATUS_CODES
                and location
                and len(redirect_chain) < probe_config.max_redirects
            ):
                redirect_chain.append(RedirectHop(status_code=status_code, location=location))
                current_url = urljoin(current_url, location)
                if not config.scope.decide(current_url).allowed:
                    error_signature = "redirect_final_url_out_of_scope"
                    break
                if normalized_method == "HEAD" and status_code == 303:
                    normalized_method = "GET"
                continue
            break
        except ProbeTimeoutError:
            error_signature = "timeout"
            response_info = None
            break
        except ValueError as exc:
            error_signature = f"invalid_url:{exc}"
            response_info = None
            break
        except (OSError, ssl.SSLError) as exc:
            error_signature = f"network_error:{type(exc).__name__}"
            response_info = None
            break

    if response_info is None:
        return failed_probe(
            url,
            normalized_method,
            final_url=current_url,
            redirect_chain=redirect_chain,
            error_signature=error_signature or "probe_failed",
        )

    status_code, headers, body = response_info
    headers_redacted = redact_headers(headers)
    content_type = headers.get("Content-Type", "")
    content_length = parse_content_length(headers.get("Content-Length"))
    text = decode_body(body, content_type)
    excerpt = redact_text(text[: min(len(text), 4000)])
    title = extract_title(text)
    body_hash = hashlib.sha256(body).hexdigest() if body else ""
    duration_ms = int((time.time() - started) * 1000)
    return ProbeResult(
        probe_id=stable_id("probe", normalized_method, url, status_code, body_hash, duration_ms),
        url=url,
        method=normalized_method,
        status_code=status_code,
        final_url=current_url,
        redirect_chain=redirect_chain,
        content_type=content_type,
        content_length=content_length if content_length is not None else len(body),
        title=title,
        body_sha256=body_hash,
        body_simhash=token_fingerprint(text),
        response_excerpt_redacted=excerpt,
        headers_redacted=headers_redacted,
        error_signature=error_signature,
        body_text=text,
    )


def socket_http_request(
    url: str,
    *,
    method: str,
    timeout_seconds: float,
    max_body_bytes: int,
    request_headers: list[str] | None = None,
) -> tuple[int, Message, bytes]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("unsupported_scheme")
    if not parsed.hostname:
        raise ValueError("missing_host")
    timeout = max(0.1, float(timeout_seconds))
    deadline = time.monotonic() + timeout
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    sock = connect_with_deadline(parsed.hostname, port, deadline)
    try:
        if parsed.scheme == "https":
            sock = wrap_ssl_with_deadline(sock, parsed.hostname, deadline)
        send_http_request(sock, parsed, method, deadline, request_headers=request_headers or [])
        return read_http_response(sock, method, max_body_bytes, deadline)
    finally:
        sock.close()


def connect_with_deadline(host: str, port: int, deadline: float) -> socket.socket:
    last_error: OSError | None = None
    for family, socktype, proto, _canonname, sockaddr in socket.getaddrinfo(
        host,
        port,
        type=socket.SOCK_STREAM,
    ):
        sock = socket.socket(family, socktype, proto)
        sock.setblocking(False)
        try:
            error = sock.connect_ex(sockaddr)
            if error == 0:
                sock.setblocking(True)
                return sock
            if error not in CONNECT_IN_PROGRESS_ERRORS:
                raise OSError(error, errno.errorcode.get(error, "connect_failed"))
            wait_for_socket(sock, deadline, write=True)
            socket_error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if socket_error != 0:
                raise OSError(socket_error, errno.errorcode.get(socket_error, "connect_failed"))
            sock.setblocking(True)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
            continue
    if last_error is not None:
        raise last_error
    raise ProbeTimeoutError("connect_timeout")


def wrap_ssl_with_deadline(sock: socket.socket, hostname: str, deadline: float) -> socket.socket:
    remaining = seconds_remaining(deadline)
    sock.settimeout(remaining)
    context = ssl.create_default_context()
    try:
        wrapped = context.wrap_socket(sock, server_hostname=hostname)
    except Exception:
        sock.close()
        raise
    wrapped.settimeout(remaining)
    return wrapped


def send_http_request(
    sock: socket.socket,
    parsed: Any,
    method: str,
    deadline: float,
    *,
    request_headers: list[str] | None = None,
) -> None:
    target = urlunparse(("", "", parsed.path or "/", parsed.params, parsed.query, ""))
    host = parsed.hostname or ""
    default_port = 443 if parsed.scheme == "https" else 80
    if parsed.port and parsed.port != default_port:
        host = f"{host}:{parsed.port}"
    header_lines = [
        f"{method} {target} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: DONZO safe-verifier/0.3",
        "Accept: */*",
    ]
    for header in request_headers or []:
        if ":" in header:
            header_lines.append(header)
    header_lines.append("Connection: close")
    request = ("\r\n".join(header_lines) + "\r\n\r\n").encode("ascii", errors="ignore")
    sock.settimeout(seconds_remaining(deadline))
    sock.sendall(request)


def read_http_response(
    sock: socket.socket,
    method: str,
    max_body_bytes: int,
    deadline: float,
) -> tuple[int, Message, bytes]:
    buffer = bytearray()
    while b"\r\n\r\n" not in buffer:
        if len(buffer) > 65536:
            raise OSError("response_headers_too_large")
        chunk = recv_with_deadline(sock, deadline)
        if not chunk:
            break
        buffer.extend(chunk)
    header_bytes, separator, remainder = bytes(buffer).partition(b"\r\n\r\n")
    if not separator:
        raise OSError("response_headers_missing")
    status_line, _, header_block = header_bytes.partition(b"\r\n")
    status_parts = status_line.decode("iso-8859-1", errors="replace").split()
    if len(status_parts) < 2:
        raise OSError("response_status_missing")
    status_code = int(status_parts[1])
    headers = parse_headers(BytesIO(header_block + b"\r\n\r\n"))
    if method == "HEAD":
        return status_code, headers, b""
    body = bytearray(remainder[:max_body_bytes])
    while len(body) < max_body_bytes:
        chunk = recv_with_deadline(sock, deadline)
        if not chunk:
            break
        body.extend(chunk[: max_body_bytes - len(body)])
    return status_code, headers, bytes(body)


def recv_with_deadline(sock: socket.socket, deadline: float) -> bytes:
    wait_for_socket(sock, deadline, write=False)
    try:
        return sock.recv(4096)
    except TimeoutError as exc:
        raise ProbeTimeoutError("read_timeout") from exc


def wait_for_socket(sock: socket.socket, deadline: float, *, write: bool) -> None:
    timeout = seconds_remaining(deadline)
    readers = [] if write else [sock]
    writers = [sock] if write else []
    readable, writable, _ = select.select(readers, writers, [], timeout)
    if write and not writable:
        raise ProbeTimeoutError("connect_timeout")
    if not write and not readable:
        raise ProbeTimeoutError("read_timeout")


def seconds_remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ProbeTimeoutError("deadline_exceeded")
    return remaining


def probe_from_record(record: dict[str, Any]) -> ProbeResult | None:
    url = str(record.get("url") or record.get("target") or "")
    if not url:
        return None
    status_code = parse_int(record.get("status_code"))
    content_type = str(record.get("content_type") or "")
    title = str(record.get("title") or "")
    if status_code is None and not content_type and not title:
        return None
    return ProbeResult(
        probe_id=stable_id("probe", "metadata", url, status_code, content_type, title),
        url=url,
        method=str(record.get("method") or "GET").upper(),
        status_code=status_code,
        final_url=url,
        content_type=content_type,
        title=title,
        content_length=parse_int(record.get("content_length")),
        error_signature=None,
    )


def failed_probe(
    url: str,
    method: str,
    *,
    final_url: str,
    redirect_chain: list[RedirectHop] | None = None,
    error_signature: str,
) -> ProbeResult:
    return ProbeResult(
        probe_id=stable_id("probe", method, url, error_signature),
        url=url,
        method=method,
        status_code=None,
        final_url=final_url,
        redirect_chain=redirect_chain or [],
        error_signature=error_signature,
    )


def read_body(response: Any, method: str, max_bytes: int) -> bytes:
    if method == "HEAD":
        return b""
    return response.read(max_bytes)


def read_error_body(exc: Any, method: str, max_bytes: int) -> bytes:
    if method == "HEAD":
        return b""
    try:
        return exc.read(max_bytes)
    except OSError:
        return b""


def redact_headers(headers: Message) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADER_NAMES:
            redacted[key] = "REDACTED"
        else:
            redacted[key] = redact_text(str(value))
    return redacted


def redact_text(text: str) -> str:
    output = text
    for pattern in SECRET_PATTERNS:
        output = pattern.sub(lambda match: f"{match.group(1)}REDACTED", output)
    return output


def decode_body(body: bytes, content_type: str) -> str:
    charset = "utf-8"
    match = re.search(r"charset=([^;\s]+)", content_type, re.IGNORECASE)
    if match:
        charset = match.group(1)
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def extract_title(text: str) -> str:
    match = TITLE_PATTERN.search(text)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:200]


def token_fingerprint(text: str) -> str:
    tokens = sorted(set(re.findall(r"[A-Za-z0-9_/-]{3,}", text.lower())))
    if not tokens:
        return ""
    return hashlib.sha256(" ".join(tokens[:200]).encode("utf-8")).hexdigest()[:16]


def parse_content_length(value: object) -> int | None:
    return parse_int(value)


def parse_int(value: object) -> int | None:
    try:
        if value in (None, ""):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def origin_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def same_origin(left: str, right: str) -> bool:
    return origin_url(left).lower() == origin_url(right).lower()
