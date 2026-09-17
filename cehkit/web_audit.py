"""Small, read-only HTTP and TLS observations using the Python standard library."""

import datetime
import http.client
import http.cookies
import ipaddress
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request


SECURITY_HEADERS = (
    "strict-transport-security", "content-security-policy", "x-content-type-options",
    "x-frame-options", "referrer-policy", "permissions-policy",
)


def validate_url(value):
    """Validate an absolute HTTP(S) URL, including an optional explicit port."""
    if any(ord(char) < 33 or ord(char) == 127 for char in value):
        raise ValueError("URL must not contain whitespace or control characters")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Use an absolute http:// or https:// URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credentials in URLs are not supported")
    if parsed.fragment:
        raise ValueError("URL fragments are not sent to servers; omit the fragment")
    try:
        port = parsed.port
        host = parsed.hostname.encode("idna").decode("ascii")
    except (UnicodeError, ValueError) as exc:
        raise ValueError("Invalid hostname or port") from exc
    if port == 0:
        raise ValueError("Port must be between 1 and 65535")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.rstrip(".").split(".")
        if len(host) > 253 or any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in labels
        ):
            raise ValueError("Invalid hostname")
    netloc = "[" + host + "]" if ":" in host else host
    if port is not None:
        netloc += ":" + str(port)
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path or "/", parsed.query, ""))


def public_url(value):
    """Do not copy query strings, which sometimes contain tokens, to reports."""
    parsed = urllib.parse.urlsplit(value)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


class SameHostRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 4
    max_repeats = 2

    def __init__(self, hostname):
        super().__init__()
        self.hostname = hostname.lower().rstrip(".")

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            newurl = validate_url(newurl)
        except ValueError as exc:
            raise urllib.error.URLError("Redirect has an invalid URL") from exc
        next_url = urllib.parse.urlsplit(newurl)
        if next_url.hostname.lower().rstrip(".") != self.hostname:
            raise urllib.error.URLError("Redirect to a different host was not followed")
        if urllib.parse.urlsplit(req.full_url).scheme == "https" and next_url.scheme == "http":
            raise urllib.error.URLError("HTTPS to HTTP redirect was not followed")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def inspect_headers(headers, is_https):
    """Summarize selected headers and cookie attributes; never return cookie values."""
    selected = {name: headers.get(name) for name in SECURITY_HEADERS if headers.get(name) is not None}
    findings = []
    for name in SECURITY_HEADERS:
        if name not in selected and (name != "strict-transport-security" or is_https):
            findings.append({"severity": "observation", "item": name, "message": "Header was absent from this response"})
    cookies = []
    unparsed = 0
    for header in headers.get_all("Set-Cookie", []):
        parsed = http.cookies.SimpleCookie()
        try:
            parsed.load(header)
        except http.cookies.CookieError:
            unparsed += 1
            continue
        if not parsed:
            unparsed += 1
        for name, cookie in parsed.items():
            flags = {
                "name": name,
                "secure": bool(cookie["secure"]),
                "httponly": bool(cookie["httponly"]),
                "samesite": cookie["samesite"].lower() or None,
            }
            cookies.append(flags)
            if is_https and not flags["secure"]:
                findings.append({"severity": "observation", "item": "cookie:" + name, "message": "Secure flag was absent"})
            if not flags["httponly"]:
                findings.append({"severity": "observation", "item": "cookie:" + name, "message": "HttpOnly flag was absent; suitability depends on the cookie's purpose"})
            if flags["samesite"] == "none" and not flags["secure"]:
                findings.append({"severity": "observation", "item": "cookie:" + name, "message": "SameSite=None was set without Secure"})
    return {"security_headers": selected, "cookies": cookies, "unparsed_cookie_headers": unparsed, "findings": findings}


def inspect_tls(url, timeout=5.0):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        return {"status": "not_applicable", "reason": "The inspected URL uses HTTP"}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=parsed.hostname) as conn:
                cert = conn.getpeercert()
                cipher = conn.cipher()
                result = {
                    "status": "ok", "certificate_verified": True,
                    "negotiated_protocol": conn.version(),
                    "cipher": cipher[0] if cipher else None,
                    "cipher_bits": cipher[2] if cipher else None,
                    "certificate_not_before": cert.get("notBefore"),
                    "certificate_not_after": cert.get("notAfter"),
                    "limitation": "One verified handshake; this does not enumerate every supported protocol or cipher",
                }
                if cert.get("notAfter"):
                    expiry = datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), datetime.timezone.utc)
                    result["certificate_days_remaining"] = (expiry - datetime.datetime.now(datetime.timezone.utc)).days
                return result
    except ssl.SSLCertVerificationError as exc:
        return {"status": "error", "certificate_verified": False, "error": "Certificate verification failed", "verification_code": exc.verify_code}
    except (OSError, ValueError) as exc:
        return {"status": "error", "error": type(exc).__name__ + ": TLS connection failed"}


def audit_url(url, timeout=5.0):
    url = validate_url(url)
    if not 0 < timeout <= 60:
        raise ValueError("Timeout must be greater than zero and at most 60 seconds")
    parsed = urllib.parse.urlsplit(url)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        SameHostRedirect(parsed.hostname),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    result = {"module": "web-audit", "target": public_url(url), "query_omitted": bool(parsed.query)}
    final_url = url
    try:
        response = None
        for method in ("HEAD", "GET"):
            request = urllib.request.Request(url, method=method, headers={"User-Agent": "ceh-kali-toolkit/1.0"})
            try:
                response = opener.open(request, timeout=timeout)
            except urllib.error.HTTPError as exc:
                response = exc
            if response.code in (405, 501) and method == "HEAD":
                response.close()
                continue
            break
        with response:
            final_url = validate_url(response.geturl())
            result.update({"status": "ok", "http_status": response.code, "method": method, "final_url": public_url(final_url)})
            result.update(inspect_headers(response.headers, urllib.parse.urlsplit(final_url).scheme == "https"))
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as exc:
        # Exception text can include redirected query strings; report the class only.
        result.update({"status": "error", "error": type(exc).__name__ + ": HTTP request failed or redirect was blocked"})
    result["tls"] = inspect_tls(final_url, timeout)
    result["limitation"] = "Observations from one response; missing headers are not proof of an exploitable vulnerability. No response body is collected."
    return result


def run(args):
    return audit_url(args.url, args.timeout)


def register(subparsers):
    parser = subparsers.add_parser("web-audit", help="Observe HTTP security headers, cookie flags and verified TLS")
    parser.add_argument("url", help="Absolute http(s) URL; an explicit port is accepted")
    parser.add_argument("--timeout", type=float, default=5.0, help="Per-connection timeout in seconds (0 < value <= 60)")
    parser.set_defaults(handler=run)
    return parser
