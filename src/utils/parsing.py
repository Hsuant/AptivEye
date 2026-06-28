"""Shared JSON response parser for LLM outputs.

Extracted from supervisor.py and worker.py where it was duplicated.
Handles common LLM output patterns: raw JSON, markdown code fences,
and bare brace-delimited JSON.
"""

from __future__ import annotations

import json
import re
from typing import Any

from src.utils.logger import get_logger

logger = get_logger(__name__)


def parse_json_response(content: str) -> dict[str, Any]:
    """Parse JSON from an LLM response, handling common formatting quirks.

    Strategy (tried in order):
      1. Direct ``json.loads`` on the raw content.
      2. Extract from `` ```json ... ``` `` or `` ``` ... ``` `` fenced blocks.
      3. Extract the first bare ``{...}`` span via regex.
      4. Return an empty dict on failure (caller is responsible for fallback).

    Args:
        content: Raw LLM response string.

    Returns:
        Parsed dict, or empty dict if no valid JSON could be extracted.
    """
    # 1. Try direct parse
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    # 2. Try extracting from markdown code blocks
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", content)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # 3. Try to find the first brace-delimited JSON object
    match = re.search(r"\{[\s\S]*\}", content)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    # 4. Give up
    logger.warning("Failed to parse JSON from response: {}...", content[:200])
    return {}
