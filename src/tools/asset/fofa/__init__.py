"""FOFA network space search engine — AptivEye sub-tool.

Architecture (adapted from FofaMap v2.0, by asaotomo / Hx0 Team):

  client.py   — FofaClient: async HTTP/2 API with retry + field downgrade
  parser.py   — Response parsers: search → NetworkSearchResult, stats/host → dict
  handler.py  — handle_fofa(): 5-mode dispatch (search/stats/host/survival/icon_hash)
  utils.py    — IconHashCalculator + FofaExporter

Design: pure data tool — NO embedded LLM calls. AI reasoning (query planning,
result analysis) is done at the agent layer via src/agent/fofa_planner.py.
"""

from src.tools.asset.fofa.client import FofaClient
from src.tools.asset.fofa.handler import FOFA_TOOL_DEFINITION, handle_fofa, register_fofa_tool
from src.tools.asset.fofa.utils import FofaExporter, IconHashCalculator

__all__ = [
    "FofaClient",
    "FOFA_TOOL_DEFINITION",
    "handle_fofa",
    "register_fofa_tool",
    "IconHashCalculator",
    "FofaExporter",
]
