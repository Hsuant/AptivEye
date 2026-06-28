"""FOFA network space search engine — AptivEye tool package.

Internal structure (inspired by FofaMap v2.0):
  client.py   — FofaClient: API calls with retry, rate-limit, field downgrade
  parser.py   — Response parsers: search results, stats aggregation, host profiling
  handler.py  — Single MCP handler: mode dispatch (search/stats/host/survival)

Exposes one tool: 'fofa' with mode parameter.
"""

from src.tools.asset.fofa.client import FofaClient
from src.tools.asset.fofa.handler import FOFA_TOOL_DEFINITION, handle_fofa, register_fofa_tool

__all__ = [
    "FofaClient",
    "FOFA_TOOL_DEFINITION",
    "handle_fofa",
    "register_fofa_tool",
]
