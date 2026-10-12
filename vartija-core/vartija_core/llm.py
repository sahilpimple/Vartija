"""Pluggable language-model backends.

  * ``rules``  - no model at all; agents fall back to deterministic logic. Always works,
                 offline, on stage, when the Wi-Fi dies.
  * ``ollama`` - local model through Ollama (already in CyberGRC-AI's stack).
  * ``openai`` - any OpenAI-compatible endpoint (hosted providers, Featherless, vLLM, LM Studio).

Every backend returns plain text; agents ask for JSON and validate it themselves.
"""

from __future__ import annotations

import json
from typing import Protocol

import httpx

from .settings import Settings


class LLMError(Exception):
    pass


class LLM(Protocol):
    name: str

    def complete(self, system: str, user: str, *, json_mode: bool = False) -> str: ...


class NoLLM:
    name = "rules"

    def complete(self, system: str, user: str, *, json_mode: bool = False) -> str:
        raise LLMError("no language model configured (VARTIJA_LLM=rules)")


class OllamaLLM:
    def __init__(self, base_url: str, model: str, timeout: float) -> None:
        self.base_url, self.model, self.timeout = base_url.rstrip("/"), model, timeout
        self.name = f"ollama:{model}"

    def complete(self, system: str, user: str, *, json_mode: bool = False) -> str:
        body = {"model": self.model, "stream": False, "options": {"temperature": 0},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        if json_mode:
            body["format"] = "json"
        try:
            r = httpx.post(f"{self.base_url}/api/chat", json=body, timeout=self.timeout)
            r.raise_for_status()
            return r.json()["message"]["content"]
        except (httpx.HTTPError, KeyError, json.JSONDecodeError) as exc:
            raise LLMError(f"ollama call failed: {exc}") from exc


class OpenAICompatibleLLM:
    def __init__(self, base_url: str, model: str, api_key: str, timeout: float) -> None:
        self.base_url, self.model, self.api_key, self.timeout = base_url.rstrip("/"), model, api_key, timeout
        self.name = f"openai:{model}"

    def complete(self, system: str, user: str, *, json_mode: bool = False) -> str:
        body = {"model": self.model, "temperature": 0,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        try:
            r = httpx.post(f"{self.base_url}/chat/completions", json=body, headers=headers, timeout=self.timeout)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, IndexError, json.JSONDecodeError) as exc:
            raise LLMError(f"LLM call failed: {exc}") from exc


def make_llm(settings: Settings) -> LLM:
    if settings.llm_backend == "ollama":
        return OllamaLLM(settings.llm_base_url, settings.llm_model, settings.llm_timeout_seconds)
    if settings.llm_backend == "openai":
        return OpenAICompatibleLLM(settings.llm_base_url, settings.llm_model, settings.llm_api_key,
                                   settings.llm_timeout_seconds)
    return NoLLM()


def parse_json_object(text: str) -> dict:
    """Models sometimes wrap JSON in prose or code fences; take the outermost object."""
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise LLMError("model did not return a JSON object")
    try:
        value = json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        raise LLMError(f"model returned invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise LLMError("model returned JSON that is not an object")
    return value
