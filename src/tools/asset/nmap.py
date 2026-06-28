"""Port scanning — nmap wrapper with socket-based fallback.

Two scanning backends:
  - nmap: Comprehensive (SYN scan, service detection, NSE scripts, OS detection).
    Requires nmap installed. Uses XML output for reliable parsing.
  - socket: Pure Python TCP connect() scan. Always available, no deps.
    Good enough for basic open-port discovery.

Common port presets for targeted scanning.
"""

from __future__ import annotations

import asyncio
import shutil
import socket
import time
import xml.etree.ElementTree as ET
from typing import Optional

from src.tools.asset.models import PortInfo, PortScanResult, PortState
from src.utils.logger import get_logger

logger = get_logger(__name__)

# ── Port presets ──────────────────────────────────────────────────────────

TOP_10: list[int] = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389]
TOP_100: list[int] = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
    2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009,
    5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 5984, 6000,
    6001, 6379, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000,
    9090, 9200, 9300, 10000, 27017, 49152,
]
TOP_1000: str = "1-1000"  # Nmap format for top 1000

PRESETS: dict[str, list[int] | str] = {
    "top10": TOP_10,
    "top100": TOP_100,
    "top1000": TOP_1000,
    "all": "1-65535",
}

# Common service name mapping by port
WELL_KNOWN: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s",
    1723: "pptp", 3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb",
}


# ── Backend: nmap ─────────────────────────────────────────────────────────


async def scan_ports_nmap(
    host: str,
    ports: str = "top100",
    timing: int = 4,
    service_detection: bool = True,
    os_detection: bool = False,
    nse_scripts: str = "",
    timeout: float = 300.0,
    sudo: bool = False,
) -> PortScanResult:
    """Scan ports using nmap with XML output parsing.

    Args:
        host: Target IP or hostname.
        ports: Port specification — preset name, range (e.g. "1-1000"), or list.
        timing: nmap timing template 0-5 (higher = faster, less accurate).
        service_detection: Enable -sV service/version detection.
        os_detection: Enable -O OS detection.
        nse_scripts: Comma-separated NSE script names (e.g. "http-title,ssl-cert").
        timeout: Max scan time in seconds.
        sudo: Use sudo for SYN scan (requires root/npcap on Windows).

    Returns:
        PortScanResult with parsed port information.
    """
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        logger.info("nmap not found in PATH — falling back to socket scan")
        return await scan_ports_socket(host, ports, timeout=min(timeout, 60.0))

    # Resolve port spec
    port_spec = PRESETS.get(ports, ports) if isinstance(ports, str) else ",".join(map(str, ports))
    if isinstance(port_spec, list):
        port_spec = ",".join(map(str, port_spec))

    # Build command
    cmd: list[str] = []
    if sudo:
        cmd.extend(["sudo"])

    cmd.extend([
        nmap_bin,
        "-sS" if not _is_windows() else "-sT",  # SYN on Linux, Connect on Windows
        f"-T{timing}",
        "-p", str(port_spec),
        "--open",
        "-oX", "-",  # XML to stdout
    ])

    if service_detection:
        cmd.append("-sV")
        cmd.append("--version-intensity")  # type: ignore[arg-type]
        cmd.append("5")
    if os_detection:
        cmd.append("-O")
        cmd.append("--osscan-guess")
    if nse_scripts:
        cmd.extend(["--script", nse_scripts])

    cmd.append(host)
    cmd_str = " ".join(cmd)

    logger.info("Running nmap: {}", cmd_str)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning("nmap timed out after {}s for {}", timeout, host)
        return PortScanResult(
            host=host,
            errors=[f"nmap timed out after {timeout}s"],
            raw_command=cmd_str,
        )
    except FileNotFoundError:
        return PortScanResult(host=host, errors=["nmap binary not found"], raw_command=cmd_str)

    # Parse XML output
    ports, errors = _parse_nmap_xml(stdout.decode(errors="replace"))
    if stderr:
        stderr_text = stderr.decode(errors="replace")[:200]
        if "WARNING" in stderr_text or "Error" in stderr_text:
            errors.append(stderr_text)

    open_ports = [p.port for p in ports if p.state == PortState.OPEN]
    os_guess = ""

    return PortScanResult(
        host=host,
        ports=ports,
        total_scanned=len(ports),
        open_ports=open_ports,
        scan_method="nmap",
        os_detection=os_guess,
        errors=errors,
        raw_command=cmd_str,
    )


def _parse_nmap_xml(xml_output: str) -> tuple[list[PortInfo], list[str]]:
    """Parse nmap XML output into PortInfo objects."""
    ports: list[PortInfo] = []
    errors: list[str] = []

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        return ports, [f"Failed to parse nmap XML: {e}"]

    for host_elem in root.findall(".//host"):
        for port_elem in host_elem.findall(".//ports/port"):
            port_id = int(port_elem.get("portid", "0"))
            protocol = port_elem.get("protocol", "tcp")

            state_elem = port_elem.find("state")
            state_str = state_elem.get("state", "closed") if state_elem is not None else "closed"
            try:
                state = PortState(state_str)
            except ValueError:
                state = PortState.CLOSED

            service_elem = port_elem.find("service")
            service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
            product = service_elem.get("product", "") if service_elem is not None else ""
            version = service_elem.get("version", "") if service_elem is not None else ""
            extrainfo = service_elem.get("extrainfo", "") if service_elem is not None else ""
            cpe = ""
            if service_elem is not None:
                for cpe_elem in service_elem.findall("cpe"):
                    cpe = cpe_elem.text or ""
                    break

            # Extract script output as banner
            banner = ""
            for script_elem in port_elem.findall("script"):
                output = script_elem.get("output", "")
                if output:
                    banner += f"[{script_elem.get('id', '')}] {output}\n"
            banner = banner.strip()

            if service_name == "unknown" and port_id in WELL_KNOWN:
                service_name = WELL_KNOWN[port_id]

            ports.append(PortInfo(
                port=port_id,
                protocol=protocol,
                state=state,
                service=service_name,
                product=product,
                version=version,
                extrainfo=extrainfo,
                cpe=cpe,
                banner=banner[:1000],
            ))

    return ports, errors


# ── Backend: socket (pure Python fallback) ─────────────────────────────────


async def scan_ports_socket(
    host: str,
    ports: str | list[int] = "top100",
    timeout: float = 60.0,
    per_port_timeout: float = 1.0,
) -> PortScanResult:
    """Scan ports using pure Python TCP connect() — no external dependencies.

    Honest about limitations: no SYN stealth, no service detection, slower.
    Use when nmap is not available.

    Args:
        host: Target IP or hostname (hostnames resolved via DNS first).
        ports: Port specification — preset name or list of ints.
        timeout: Max total scan time.
        per_port_timeout: Timeout per individual port connect attempt.

    Returns:
        PortScanResult with basic port state info.
    """
    # Resolve port list
    if isinstance(ports, str):
        port_list = PRESETS.get(ports, TOP_100)
        if isinstance(port_list, str):
            # Range like "1-1000"
            import re
            m = re.match(r"(\d+)-(\d+)", port_list)
            if m:
                port_list = list(range(int(m.group(1)), int(m.group(2)) + 1))
            else:
                port_list = TOP_100
    else:
        port_list = ports

    if isinstance(port_list, str):
        port_list = TOP_100  # Final safety net

    # Limit total ports to avoid excessive scan time
    if len(port_list) > 1000:
        logger.warning("Limiting socket scan to first 1000 of {} ports", len(port_list))
        port_list = port_list[:1000]

    start = time.monotonic()
    results: list[PortInfo] = []
    semaphore = asyncio.Semaphore(50)  # Max concurrent connects

    async def _check_port(port: int) -> None:
        nonlocal results
        async with semaphore:
            elapsed = time.monotonic() - start
            if elapsed > timeout:
                return

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=per_port_timeout,
                )
                writer.close()
                await writer.wait_closed()

                service_name = WELL_KNOWN.get(port, "unknown")
                # Try to grab a banner
                banner = ""
                try:
                    banner_reader, banner_writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=min(per_port_timeout, 2.0),
                    )
                    try:
                        data = await asyncio.wait_for(
                            banner_reader.read(1024),
                            timeout=1.0,
                        )
                        banner = data.decode(errors="replace")[:500]
                    except asyncio.TimeoutError:
                        pass
                    banner_writer.close()
                    await banner_writer.wait_closed()
                except Exception:
                    pass

                results.append(PortInfo(
                    port=port,
                    protocol="tcp",
                    state=PortState.OPEN,
                    service=service_name,
                    banner=banner,
                ))
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                pass  # Port closed or filtered — not interesting

    tasks = [_check_port(p) for p in port_list]
    await asyncio.gather(*tasks, return_exceptions=True)

    duration = time.monotonic() - start
    open_ports = [p.port for p in results]

    # Sort by port number
    results.sort(key=lambda p: p.port)

    logger.info("Socket scan: {} open ports on {} in {:.1f}s", len(results), host, duration)

    return PortScanResult(
        host=host,
        ports=results,
        total_scanned=len(port_list),
        open_ports=open_ports,
        scan_method="socket",
        scan_duration_seconds=round(duration, 2),
        errors=[] if duration < timeout else [f"Socket scan timed out after {timeout}s"],
    )


# ── Main entry point ──────────────────────────────────────────────────────


async def discover_ports(
    host: str,
    *,
    ports: str = "top100",
    prefer_nmap: bool = True,
    service_detection: bool = True,
    timing: int = 4,
    timeout: float = 300.0,
) -> PortScanResult:
    """Scan ports on a host, preferring nmap with socket fallback.

    This is the primary entry point called by the MCP Server tool handler.

    Args:
        host: Target IP or hostname.
        ports: Port specification (preset name, range, or comma-separated).
        prefer_nmap: Use nmap if available; fall back to socket.
        service_detection: Enable service/version detection (nmap only).
        timing: nmap timing 0-5.
        timeout: Max scan time in seconds.

    Returns:
        PortScanResult with all discovered ports.
    """
    if prefer_nmap and shutil.which("nmap"):
        return await scan_ports_nmap(
            host, ports=ports, timing=timing,
            service_detection=service_detection, timeout=timeout,
        )
    else:
        return await scan_ports_socket(host, ports=ports, timeout=min(timeout, 120.0))


# ── Helpers ────────────────────────────────────────────────────────────────

def _is_windows() -> bool:
    import sys
    return sys.platform == "win32"
