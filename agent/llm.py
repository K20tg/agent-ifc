"""The single model seam: one raw POST to Ollama's /api/chat over urllib, so the
exact wire payload is visible and loggable. No SDK, no framework.

Swap the whole backend by editing only this file.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field

from agent import config


@dataclass
class ToolCall:
    name: str
    args: dict
    raw: dict  # original Ollama tool_call dict, for faithful re-serialization


@dataclass
class ModelReply:
    content: str
    tool_calls: list = field(default_factory=list)  # list[ToolCall]
    raw_message: dict = field(default_factory=dict)


def call_model(messages, tools):
    """One turn. Returns a ModelReply. Raises RuntimeError with a helpful
    message if Ollama is unreachable or errors.
    """
    payload = {
        "model": config.MODEL,
        "messages": messages,
        "tools": tools,
        "stream": False,
        "options": {"temperature": config.TEMPERATURE},
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        config.OLLAMA_CHAT_ENDPOINT,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        raise RuntimeError(f"Ollama HTTP {e.code} from {config.OLLAMA_CHAT_ENDPOINT}: {detail}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(
            f"Cannot reach Ollama at {config.OLLAMA_CHAT_ENDPOINT} ({e}). "
            f"Is `ollama serve` running and is model {config.MODEL!r} pulled?"
        ) from e

    msg = body.get("message", {}) or {}
    content = msg.get("content", "") or ""
    calls = []
    for tc in (msg.get("tool_calls") or []):
        fn = tc.get("function", {}) or {}
        name = fn.get("name", "")
        args = fn.get("arguments", {})
        if isinstance(args, str):          # some builds return a JSON string
            try:
                args = json.loads(args)
            except Exception:
                args = {"_raw": args}
        if not isinstance(args, dict):
            args = {}
        calls.append(ToolCall(name=name, args=args, raw=tc))
    return ModelReply(content=content, tool_calls=calls, raw_message=msg)
