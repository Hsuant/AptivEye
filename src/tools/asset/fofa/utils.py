"""FOFA utilities — icon hash calculator and result exporter.

IconHashCalculator: mmh3-based favicon hash for icon-based FOFA search.
FofaExporter: styled Excel (.xlsx) and CSV export for FOFA results.

Adapted from FofaMap v2.0 (by asaotomo / Hx0 Team).
"""

from __future__ import annotations

import codecs
import csv
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from src.utils.logger import get_logger

logger = get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Icon Hash Calculator
# ═══════════════════════════════════════════════════════════════════════════


class IconHashCalculator:
    """Calculate FOFA-compatible icon_hash from a target's favicon.ico.

    Downloads the favicon, base64-encodes it, and computes the mmh3 hash
    matching FOFA's icon_hash search syntax.

    Usage::

        result = await IconHashCalculator.get_hash("https://example.com")
        # → 'icon_hash="-123456789"'
    """

    @staticmethod
    async def get_hash(url: str, timeout: float = 10.0) -> str | None:
        """Calculate FOFA icon_hash for a URL.

        Args:
            url: Target URL or host (http:// added if missing).
            timeout: HTTP request timeout in seconds.

        Returns:
            FOFA query fragment like 'icon_hash="-123456789"', or None.
        """
        try:
            import mmh3
        except ImportError:
            logger.error("mmh3 required for icon hash. Install: pip install mmh3")
            return None

        if not url.startswith("http"):
            url = f"http://{url}"

        parsed = urlparse(url)
        favicon_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"

        logger.info("Downloading favicon: {}", favicon_url)

        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=httpx.Timeout(timeout),
                follow_redirects=True,
            ) as client:
                resp = await client.get(favicon_url)
                if resp.status_code == 200:
                    icon_hash = mmh3.hash(
                        codecs.lookup("base64").encode(resp.content)[0]
                    )
                    result = f'icon_hash="{icon_hash}"'
                    logger.info("Icon hash: {}", result)
                    return result
                logger.warning("Favicon not found (HTTP {})", resp.status_code)
                return None
        except Exception as exc:
            logger.warning("Icon hash failed for {}: {}", url, exc)
            return None

    @staticmethod
    async def build_query(
        url: str,
        extra: str = "",
        timeout: float = 10.0,
    ) -> str | None:
        """Build a complete FOFA query from icon_hash + optional terms.

        Example:
            >>> await IconHashCalculator.build_query(
            ...     "https://example.com", extra='country="CN"'
            ... )
            'icon_hash="-123456789" && country="CN"'
        """
        icon = await IconHashCalculator.get_hash(url, timeout=timeout)
        if not icon:
            return None
        return f"{icon} && {extra}" if extra else icon


# ═══════════════════════════════════════════════════════════════════════════
# FOFA Result Exporter
# ═══════════════════════════════════════════════════════════════════════════


class FofaExporter:
    """Export FOFA search results to Excel (.xlsx) or CSV.

    Supports single-sheet and multi-sheet (batch merge) exports
    with styled headers via xlsxwriter.

    Usage::

        exporter = FofaExporter(output_dir="./results")
        path = exporter.save(data=rows, fields="host,ip,port,title")
    """

    SUPPORTED_FORMATS = {"xlsx", "csv"}

    def __init__(self, output_dir: str = "./data/reports") -> None:
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)

    # ── Public API ──────────────────────────────────────────────────

    def save(
        self,
        data: list[list[Any]] | dict[str, list[list[Any]]],
        filename: str | None = None,
        fields: str | list[str] | None = None,
        export_format: str = "xlsx",
        output_dir: str | None = None,
    ) -> Path | None:
        """Save query results to file.

        Args:
            data: List of rows (single-sheet) or dict of sheet→rows (multi-sheet).
            filename: Output name without extension.
            fields: Comma-separated field names or list for column headers.
            export_format: "xlsx" or "csv".
            output_dir: Override output directory.

        Returns:
            Path to the exported file, or None if no data.
        """
        if not data:
            logger.warning("No data to export")
            return None

        fmt = self._norm_fmt(export_format)
        path = self._resolve_path(filename, fmt, output_dir)
        headers = self._norm_headers(fields)

        try:
            if fmt == "csv":
                self._write_csv(data, path, headers)
            else:
                self._write_xlsx(data, path, headers)
            logger.info("{} exported: {}", fmt.upper(), path)
            return path
        except Exception as exc:
            logger.error("Export failed: {}", exc)
            return None

    # ── Internal helpers ────────────────────────────────────────────

    def _norm_fmt(self, fmt: str) -> str:
        f = fmt.lower().strip(".")
        return f if f in self.SUPPORTED_FORMATS else "xlsx"

    def _resolve_path(
        self, filename: str | None, fmt: str, output_dir: str | None
    ) -> Path:
        od = Path(output_dir) if output_dir else self._output_dir
        od.mkdir(parents=True, exist_ok=True)
        if filename:
            return (od / filename).with_suffix(f".{fmt}")
        ts = time.strftime("%Y%m%d_%H%M%S")
        return od / f"fofa_result_{ts}.{fmt}"

    @staticmethod
    def _norm_headers(fields: str | list[str] | None) -> list[str]:
        if fields is None:
            raw = ["host", "ip", "port", "protocol", "title", "domain", "country"]
        elif isinstance(fields, str):
            raw = [f.strip() for f in fields.split(",") if f.strip()]
        else:
            raw = [str(f).strip() for f in fields if str(f).strip()]
        return ["ID"] + [f.upper() for f in raw]

    @staticmethod
    def _norm_row(item: Any, ncols: int) -> list[str]:
        if isinstance(item, (list, tuple)):
            row = list(item)
        else:
            row = [item]
        row = ["" if v is None else str(v) for v in row]
        if len(row) < ncols:
            row.extend([""] * (ncols - len(row)))
        return row[:ncols]

    # ── Excel (.xlsx) ───────────────────────────────────────────────

    def _write_xlsx(
        self,
        data: list[list[Any]] | dict[str, list[list[Any]]],
        path: Path,
        headers: list[str],
    ) -> None:
        import xlsxwriter

        wb = xlsxwriter.Workbook(str(path))

        hdr_fmt = wb.add_format({
            "bold": True, "font_color": "white", "bg_color": "#4BACC6",
            "align": "center", "valign": "vcenter", "border": 1, "font_size": 12,
        })
        cell_fmt = wb.add_format({
            "border": 1, "align": "left", "valign": "vcenter", "text_wrap": False,
        })
        id_fmt = wb.add_format({"border": 1, "align": "center", "valign": "vcenter"})

        ncols = len(headers) - 1  # minus ID column

        def _write_sheet(name: str, rows: list[list[Any]]) -> None:
            clean = re.sub(r"[\[\]:*?/\\]", "_", str(name))[:31]
            ws = wb.add_worksheet(clean)
            ws.set_row(0, 25)
            for ci, h in enumerate(headers):
                ws.write(0, ci, h, hdr_fmt)
                w = 30 if h in ("URL", "HOST", "TITLE") else 10 if h in ("ID", "PORT") else 20
                ws.set_column(ci, ci, w)
            for ri, item in enumerate(rows, start=1):
                ws.write(ri, 0, ri, id_fmt)
                for ci, val in enumerate(self._norm_row(item, ncols), start=1):
                    ws.write(ri, ci, val, cell_fmt)

        if isinstance(data, dict):
            for sn, sd in data.items():
                if sd:
                    _write_sheet(sn, sd)
            logger.info("Multi-sheet xlsx: {} sheets", len(data))
        else:
            _write_sheet("FOFA Assets", data)

        wb.close()

    # ── CSV ─────────────────────────────────────────────────────────

    def _write_csv(
        self,
        data: list[list[Any]] | dict[str, list[list[Any]]],
        path: Path,
        headers: list[str],
    ) -> None:
        ncols = len(headers) - 1
        with open(path, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f)
            if isinstance(data, dict):
                w.writerow(["QUERY"] + headers)
                for qname, rows in data.items():
                    if not rows:
                        continue
                    for ri, item in enumerate(rows, start=1):
                        w.writerow([qname, ri] + self._norm_row(item, ncols))
            else:
                w.writerow(headers)
                for ri, item in enumerate(data, start=1):
                    w.writerow([ri] + self._norm_row(item, ncols))
