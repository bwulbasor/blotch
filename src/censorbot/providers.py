"""Provider adapters: connect the :class:`~censorbot.gateway.Gateway` to real
services (plan §12/§13). A provider is any ``str -> str`` callable, so the gateway
stays agnostic; these are convenience adapters, all dependency-free (stdlib only).

**Only sanitised text is ever passed to a provider.** These adapters transmit
exactly what the gateway hands them - the tokenised document - and never touch the
vault. Point them at ChatGPT, Claude, a local model server, or anything that
speaks JSON over HTTP.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any, Callable

Provider = Callable[[str], str]


def _dig(obj: Any, path: str) -> Any:
    """Follow a dotted path with numeric indices: ``choices.0.message.content``."""

    cur = obj
    for part in path.split("."):
        if isinstance(cur, list):
            cur = cur[int(part)]
        else:
            cur = cur[part]
    return cur


class HttpProvider:
    """A generic JSON-over-HTTP provider.

    Parameters
    ----------
    url:
        The endpoint to POST to.
    build_payload:
        ``sanitized_text -> dict`` producing the request body. Defaults to
        ``{"input": text}``.
    response_path:
        Dotted path into the JSON response holding the reply text (e.g.
        ``choices.0.message.content`` for OpenAI-compatible chat APIs). If
        ``None``, the whole response body is returned as text.
    headers:
        Extra request headers (e.g. ``{"Authorization": "Bearer …"}``). Supply
        secrets yourself; censorbot does not store them.
    timeout:
        Seconds.
    """

    def __init__(self, url: str, *,
                 build_payload: Callable[[str], dict] | None = None,
                 response_path: str | None = None,
                 headers: dict[str, str] | None = None,
                 timeout: float = 60.0) -> None:
        self.url = url
        self.build_payload = build_payload or (lambda t: {"input": t})
        self.response_path = response_path
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.timeout = timeout

    def __call__(self, text: str) -> str:
        body = json.dumps(self.build_payload(text)).encode("utf-8")
        req = urllib.request.Request(self.url, data=body, headers=self.headers,
                                     method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            raw = resp.read().decode("utf-8")
        if self.response_path is None:
            return raw
        return str(_dig(json.loads(raw), self.response_path))


def openai_chat_provider(url: str, api_key: str, model: str,
                         system: str = "") -> HttpProvider:
    """An OpenAI-compatible /chat/completions adapter.

    Works with OpenAI, many local servers (llama.cpp, vLLM, Ollama's OpenAI
    shim), and Azure-style gateways. Only the sanitised text becomes the user
    message.
    """

    def payload(text: str) -> dict:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": text})
        return {"model": model, "messages": messages}

    return HttpProvider(
        url,
        build_payload=payload,
        response_path="choices.0.message.content",
        headers={"Authorization": f"Bearer {api_key}"},
    )
