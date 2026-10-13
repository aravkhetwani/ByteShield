"""Heuristic detection of tool poisoning and prompt injection.

Two scopes:
* ``definition`` - tool name/description/schema text (what the *model* reads when choosing tools)
* ``response``   - text returned by a tool call (indirect prompt injection)

Each rule contributes its weight once; the score is the capped sum (0-100).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class Rule:
    id: str
    pattern: re.Pattern[str]
    weight: int
    description: str
    scopes: frozenset[str] = frozenset({"definition", "response"})


def _r(id_: str, pattern: str, weight: int, description: str, scopes: Iterable[str] = ("definition", "response")) -> Rule:
    return Rule(id_, re.compile(pattern, re.IGNORECASE | re.DOTALL), weight, description, frozenset(scopes))


RULES: list[Rule] = [
    _r("hidden_instruction_tag",
       r"<\s*/?\s*(important|system|instructions?|secret|hidden|admin|override)\s*>", 40,
       "Hidden instruction block (<IMPORTANT>-style tag)"),
    _r("ignore_previous",
       r"(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|system)\s+"
       r"(instructions?|rules?|prompts?|messages?|guidelines?)", 45,
       "Attempts to override earlier instructions"),
    _r("concealment",
       r"(do\s*n[o']t|never|without)\s+(tell|mention|reveal|inform|disclose|notify|show|telling|informing|"
       r"mentioning|notifying)[^.\n]{0,60}\b(user|human|operator|anyone)\b|could even upset the user|"
       r"do not mention that you", 45,
       "Instructs the model to hide actions from the user"),
    _r("sensitive_path",
       r"(~|\$HOME|%USERPROFILE%)?[\\/]?\.(ssh|aws|gnupg|kube)\b|\bid_(rsa|ed25519|ecdsa)\b|(^|[\s/\\])\.env\b|"
       r"/etc/(passwd|shadow)|\bcredentials?\b|\bprivate key\b|\bapi[_ -]?keys?\b|\bsecret[_ ]?keys?\b", 35,
       "References credentials or sensitive files"),
    _r("read_before_use",
       r"before\s+(using|calling|running|invoking|you\s+use)\s+(this|the)\s+(tool|function)[^.]{0,120}"
       r"\b(read|open|cat|fetch|send|include|pass|provide)\b", 35,
       "Demands side-effect actions before the tool can be used"),
    _r("exfiltration",
       r"\b(send|forward|post|upload|transmit|leak|e-?mail\s+(it|them|this|that|the|its|all|everything|me))\b"
       r"[^.\n]{0,80}(\bto\b|\bat\b)\s+(https?://\S+|[\w.+-]+@[\w-]+\.[\w.-]+)", 40,
       "Instructs sending data to an external destination"),
    _r("cross_tool_manipulation",
       r"\b(also|first|then|additionally)\s+(call|use|invoke|run|execute)\s+(the\s+)?[\w.\-]+\s+(tool|function)|"
       r"\b(instead of|rather than|replaces?)\s+(using\s+)?(the\s+)?[\w.\-]+\s+(tool|function)|"
       r"\b(use|call)\s+(the\s+)?send_?email\b", 30,
       "Tries to steer the model into calling other tools"),
    _r("role_hijack",
       r"\byou\s+are\s+now\b|\bnew\s+instructions?\b|\bsystem\s+prompt\b|\byour\s+(new\s+)?(task|role|goal)\s+is\b|"
       r"\bAI\s+assistant\s*:|\bSYSTEM\s*:", 35,
       "Attempts to reassign the model's role"),
    _r("invisible_unicode", "[​-‏‪-‮⁠-⁤﻿]", 40,
       "Invisible / bidirectional Unicode characters"),
    _r("encoded_payload", r"[A-Za-z0-9+/]{80,}={0,2}", 20, "Long base64-like blob"),
]

PARAM_SMUGGLING_WEIGHT = 15
SUSPICIOUS_PARAM_NAMES = {"sidenote", "side_note", "notes", "note", "context", "memory", "system_prompt",
                          "instructions", "prompt", "conversation_history", "history", "scratchpad", "metadata"}
MAX_DESCRIPTION_CHARS = 2000


def _walk_schema_text(node: Any, path: str = "inputSchema") -> Iterable[tuple[str, str]]:
    """Yield (location, text) for every human/LLM-visible string in a JSON schema."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("description", "title") and isinstance(value, str):
                yield f"{path}.{key}", value
            elif key in ("default", "const", "examples") and isinstance(value, str):
                yield f"{path}.{key}", value
            elif key == "enum" and isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        yield f"{path}.enum[{i}]", item
            else:
                yield from _walk_schema_text(value, f"{path}.{key}")
    elif isinstance(node, list):
        for i, item in enumerate(node):
            yield from _walk_schema_text(item, f"{path}[{i}]")


def _excerpt(text: str, match: re.Match[str], width: int = 70) -> str:
    start, end = max(0, match.start() - 15), min(len(text), match.end() + width)
    return re.sub(r"\s+", " ", text[start:end]).strip()


def scan_texts(texts: Iterable[tuple[str, str]], scope: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for location, text in texts:
        for rule in RULES:
            if scope not in rule.scopes or rule.id in seen:
                continue
            match = rule.pattern.search(text)
            if match:
                seen.add(rule.id)
                findings.append({"rule": rule.id, "weight": rule.weight, "description": rule.description,
                                 "location": location, "excerpt": _excerpt(text, match)})
    return {"score": min(100, sum(f["weight"] for f in findings)), "findings": findings}


def scan_tool_definition(name: str, description: str, input_schema: dict[str, Any] | None) -> dict[str, Any]:
    """Score a tool definition for poisoning. Returns {"score": int, "findings": [...]}"""
    texts: list[tuple[str, str]] = [("name", name or ""), ("description", description or "")]
    schema = input_schema or {}
    texts.extend(_walk_schema_text(schema))
    result = scan_texts(texts, "definition")
    findings = result["findings"]

    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
    smuggled = [p for p in props if p.lower() in SUSPICIOUS_PARAM_NAMES]
    if smuggled:
        findings.append({"rule": "parameter_smuggling", "weight": PARAM_SMUGGLING_WEIGHT,
                         "description": "Suspicious parameter name that can smuggle data to the server",
                         "location": "inputSchema.properties", "excerpt": ", ".join(smuggled)})
    if len(description or "") > MAX_DESCRIPTION_CHARS:
        findings.append({"rule": "excessive_length", "weight": 15,
                         "description": f"Description longer than {MAX_DESCRIPTION_CHARS} characters",
                         "location": "description", "excerpt": f"{len(description)} chars"})
    return {"score": min(100, sum(f["weight"] for f in findings)), "findings": findings}


def scan_response_text(text: str) -> dict[str, Any]:
    """Score tool output for indirect prompt injection."""
    return scan_texts([("response", text or "")], "response")
