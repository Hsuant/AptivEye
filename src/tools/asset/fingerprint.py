"""Service fingerprinting — HTTP/TLS banner analysis.

Identifies running software, versions, and configurations on open ports.
Focuses on:
  - HTTP/HTTPS: headers, title, server, technologies
  - TLS: certificate extraction, cipher analysis
  - Generic: banner matching against known signatures

Designed to consume PortScanResult and enrich with FingerprintResult.
"""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
import time
from typing import Optional

import httpx

from src.tools.asset.models import FingerprintResult, PortInfo, PortScanResult, ServiceFingerprint
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Common technology fingerprints from response patterns
TECH_SIGNATURES: dict[str, list[str]] = {
    "jQuery": [r"jquery[.-]?(\d[\d.]*)?\.js", r"jQuery\s*v?(\d[\d.]*)"],
    "Bootstrap": [r"bootstrap[.-]?(\d[\d.]*)?\.css", r"bootstrap[.-]?(\d[\d.]*)?\.js"],
    "React": [r"react[.-]?(\d[\d.]*)?\.js", r"__REACT_DEVTOOLS_GLOBAL_HOOK__"],
    "Vue.js": [r"vue[.-]?(\d[\d.]*)?\.js", r"__vue__"],
    "Angular": [r"angular[.-]?(\d[\d.]*)?\.js", r"ng-version"],
    "WordPress": [r"wp-content", r"wordpress"],
    "Drupal": [r"Drupal\.settings", r"drupal\.js"],
    "PHP": [r"X-Powered-By:\s*PHP", r"\.php"],
    "ASP.NET": [r"__VIEWSTATE", r"X-AspNet-Version"],
    "Nginx": [r"Server:\s*nginx"],
    "Apache": [r"Server:\s*Apache"],
    "Cloudflare": [r"cf-ray", r"__cfduid"],
    "Fastly": [r"X-Served-By:\s*.*fastly"],
    "Akamai": [r"X-Akamai-"],
}


# ── HTTP/HTTPS fingerprinting ──────────────────────────────────────────────


async def fingerprint_http(
    host: str,
    port: int,
    use_ssl: bool = False,
    path: str = "/",
    timeout: float = 10.0,
) -> ServiceFingerprint:
    """Fingerprint an HTTP/HTTPS service.

    Retrieves headers, page title, and identifies common technologies.
    """
    scheme = "https" if use_ssl else "http"
    url = f"{scheme}://{host}:{port}{path}"
    fp = ServiceFingerprint(host=host, port=port, service_name="http" if not use_ssl else "https")

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            verify=False,  # Allow self-signed certs for scanning
            follow_redirects=True,
            max_redirects=5,
        ) as client:
            response = await client.get(url)
    except httpx.ConnectError:
        fp.service_name = "https" if use_ssl else "http"
        fp.banner = "Connection refused (TLS handshake failed or port closed)"
        return fp
    except httpx.TimeoutException:
        fp.service_name = "https" if use_ssl else "http"
        fp.banner = "Connection timed out"
        return fp
    except Exception as exc:
        fp.banner = f"Error: {exc}"[:200]
        return fp

    # Headers
    fp.http_headers = dict(response.headers)
    fp.http_status_code = response.status_code
    fp.http_server = response.headers.get("Server", "")

    # Extract title
    body = response.text[:10000]
    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    fp.http_title = title_match.group(1).strip()[:200] if title_match else ""

    # Detect technologies
    technologies: list[str] = []
    body_lower = body.lower()
    headers_str = str(response.headers).lower()

    for tech, patterns in TECH_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, body_lower, re.IGNORECASE) or re.search(pattern, headers_str, re.IGNORECASE):
                technologies.append(tech)
                break

    fp.http_technologies = technologies
    fp.banner = f"HTTP/{response.http_version} {response.status_code} {fp.http_server}"

    # Store first 500 chars of body as raw_response
    fp.raw_response = body[:500]

    return fp


# ── TLS certificate extraction ─────────────────────────────────────────────


async def fingerprint_tls(
    host: str,
    port: int = 443,
    timeout: float = 10.0,
) -> ServiceFingerprint:
    """Extract TLS/SSL certificate information from a service.

    Performs a TLS handshake and extracts certificate fields:
    subject, issuer, validity period, Subject Alternative Names.
    """
    fp = ServiceFingerprint(host=host, port=port, service_name="tls")

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Allow self-signed

        loop = asyncio.get_event_loop()

        def _grab_cert() -> dict:
            sock = socket.create_connection((host, port), timeout=timeout)
            try:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    tls_ver = ssock.version()
                    if cert is None:
                        return {"error": "No certificate returned", "version": tls_ver}

                    san: list[str] = []
                    for field in cert.get("subjectAltName", []):
                        san.append(field[1])

                    return {
                        "subject": ", ".join(
                            f"{k}={v}" for item in cert.get("subject", []) for k, v in item
                        ),
                        "issuer": ", ".join(
                            f"{k}={v}" for item in cert.get("issuer", []) for k, v in item
                        ),
                        "not_before": cert.get("notBefore", ""),
                        "not_after": cert.get("notAfter", ""),
                        "san": san,
                        "version": tls_ver,
                    }
            finally:
                sock.close()

        cert_info = await asyncio.wait_for(
            loop.run_in_executor(None, _grab_cert),
            timeout=timeout,
        )

        fp.tls_subject = cert_info.get("subject", "")
        fp.tls_issuer = cert_info.get("issuer", "")
        fp.tls_not_before = cert_info.get("not_before", "")
        fp.tls_not_after = cert_info.get("not_after", "")
        fp.tls_san = cert_info.get("san", [])
        fp.tls_version = cert_info.get("version", "")

        if "error" in cert_info:
            fp.banner = cert_info["error"]
        else:
            fp.banner = f"TLS {fp.tls_version} | Subject: {fp.tls_subject[:80]}"

    except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError) as exc:
        fp.banner = f"TLS connection failed: {exc}"[:200]
    except asyncio.TimeoutError:
        fp.banner = "TLS connection timed out"

    return fp


# ── Generic service banner grab ────────────────────────────────────────────


async def grab_banner(
    host: str,
    port: int,
    timeout: float = 5.0,
    probe_data: bytes | None = None,
) -> str:
    """Connect to a TCP port and grab the initial banner.

    Args:
        host: Target host.
        port: Port number.
        timeout: Connection timeout.
        probe_data: Optional data to send after connection (e.g., b"HEAD / HTTP/1.0\r\n\r\n").

    Returns:
        Decoded banner text (first 1000 bytes).
    """
    try:
        loop = asyncio.get_event_loop()

        def _connect_and_read() -> str:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.settimeout(timeout)
            try:
                if probe_data:
                    sock.sendall(probe_data)
                data = sock.recv(4096)
                return data.decode(errors="replace")[:1000]
            except (socket.timeout, OSError):
                return ""
            finally:
                sock.close()

        banner = await asyncio.wait_for(
            loop.run_in_executor(None, _connect_and_read),
            timeout=timeout + 2,
        )
        return banner
    except Exception:
        return ""


# ── Main entry point ──────────────────────────────────────────────────────


async def fingerprint_services(
    host: str,
    ports: list[PortInfo],
    *,
    timeout_per_service: float = 10.0,
) -> FingerprintResult:
    """Fingerprint all services on open ports of a host.

    Routes to the appropriate fingerprinter based on detected service:
      - http/https → HTTP header + technology analysis
      - https/ssl → TLS certificate extraction
      - generic → banner grab

    Args:
        host: Target IP or hostname.
        ports: List of PortInfo from a port scan.
        timeout_per_service: Max time per individual fingerprint.

    Returns:
        FingerprintResult with detailed service fingerprints.
    """
    errors: list[str] = []
    fingerprints: list[ServiceFingerprint] = []

    async def _fingerprint(pi: PortInfo) -> ServiceFingerprint | None:
        service = pi.service.lower()
        port = pi.port

        try:
            if service in ("http", "http-proxy") or port in (80, 8080, 8000, 8888):
                return await fingerprint_http(host, port, use_ssl=False, timeout=timeout_per_service)

            elif service in ("https", "https-alt") or port in (443, 8443):
                fp_http = await fingerprint_http(host, port, use_ssl=True, timeout=timeout_per_service)
                fp_tls = await fingerprint_tls(host, port, timeout=timeout_per_service)
                # Merge: HTTP fingerprint gets the TLS info
                fp_http.tls_subject = fp_tls.tls_subject
                fp_http.tls_issuer = fp_tls.tls_issuer
                fp_http.tls_not_before = fp_tls.tls_not_before
                fp_http.tls_not_after = fp_tls.tls_not_after
                fp_http.tls_san = fp_tls.tls_san
                fp_http.tls_version = fp_tls.tls_version
                if fp_tls.banner:
                    fp_http.banner += f" | {fp_tls.banner}"
                return fp_http

            else:
                # Generic banner grab
                banner = await grab_banner(host, port, timeout=min(timeout_per_service, 5.0))
                return ServiceFingerprint(
                    host=host,
                    port=port,
                    service_name=pi.service,
                    banner=banner,
                    raw_response=banner[:500],
                )
        except Exception as exc:
            errors.append(f"Fingerprint {host}:{port}: {exc}")
            return None

    tasks = [_fingerprint(pi) for pi in ports if pi.state.value == "open"]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, ServiceFingerprint):
            fingerprints.append(result)
        elif isinstance(result, Exception):
            errors.append(str(result))

    return FingerprintResult(
        host=host,
        fingerprints=fingerprints,
        total_services=len(fingerprints),
        errors=errors,
    )
