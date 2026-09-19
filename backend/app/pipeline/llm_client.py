"""
Ollama client wrapper for TraceCTF.

All AI reasoning happens through this single client — no other module
should call Ollama's HTTP API directly. This centralizes retry logic,
timeout handling, and JSON-extraction from the model's raw text output,
since local LLMs don't always return perfectly clean JSON even when asked to.
"""

from __future__ import annotations

import json
import re
from typing import Optional

import httpx

from app.config import settings


class LlmUnavailableError(Exception):
    """Raised when Ollama cannot be reached or fails after retries."""
    pass


def _extract_json(raw_text: str) -> Optional[dict]:
    """
    Local LLMs frequently wrap JSON in markdown fences or add stray text
    before/after it. This pulls out the first {...} block and parses it,
    rather than assuming raw_text is pure JSON.
    """
    raw_text = raw_text.strip()

    # Strip markdown code fences if present
    fence_match = re.search(r"```(?:json)?\s*(.*?)\s*```", raw_text, re.DOTALL)
    if fence_match:
        raw_text = fence_match.group(1)

    # Find the first balanced {...} block
    brace_match = re.search(r"\{.*\}", raw_text, re.DOTALL)
    candidate = brace_match.group(0) if brace_match else raw_text

    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        return None


class OllamaClient:
    def __init__(self):
        self.base_url = settings.ollama_base_url
        self.model = settings.ollama_model
        self.timeout = settings.ollama_timeout_seconds
        self.max_retries = settings.llm_max_retries

    async def is_available(self) -> bool:
        """Quick health check — used at startup and by the fallback logic."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                return resp.status_code == 200
        except httpx.HTTPError:
            return False

    async def generate_json(self, prompt: str, system: Optional[str] = None) -> Optional[dict]:
        """
        Sends a prompt to Ollama expecting a JSON object back.
        Returns None (never raises) if the model is unreachable or the
        output can't be parsed after retries — callers must handle None
        by falling back to rule-based logic (see rule_classifier.py).
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system or "",
            "stream": False,
            "format": "json",  # Ollama's structured-output hint; still validate below
        }

        last_error: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(f"{self.base_url}/api/generate", json=payload)
                    resp.raise_for_status()
                    data = resp.json()
                    raw_text = data.get("response", "")
                    parsed = _extract_json(raw_text)
                    if parsed is not None:
                        return parsed
                    # Parsed as None means bad JSON — worth a retry
                    last_error = ValueError(f"Could not parse JSON from LLM response: {raw_text[:200]}")
            except httpx.HTTPError as e:
                last_error = e
            except Exception as e:
                last_error = e

        # All retries exhausted — return None rather than raising, so
        # callers can gracefully fall back to rule-based classification
        # instead of crashing the pipeline (NFR-4).
        return None
    
    async def generate_text(self, prompt: str, system: Optional[str] = None) -> Optional[str]:
        """
        Like generate_json, but for free-form text output (e.g., write-up
        prose) rather than structured JSON. Returns None on failure so
        callers can fall back gracefully, same contract as generate_json.
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system or "",
            "stream": False,
        }

        for attempt in range(self.max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(f"{self.base_url}/api/generate", json=payload)
                    resp.raise_for_status()
                    data = resp.json()
                    text = data.get("response", "").strip()
                    if text:
                        return text
            except httpx.HTTPError:
                continue
            except Exception:
                continue

        return None