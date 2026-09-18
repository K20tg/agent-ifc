"""The centralized, labeled context store — the single seam this whole project
is architected around.

Every element the model ever sees enters through an ``add_*`` method and leaves
through exactly one function, ``assemble()``. Each element carries a provenance
label (``Origin``) and, for tool results, the tool that produced it (``source``).

PHASE 1: the labels were *carried but not enforced*.

PHASE 2 (implemented below): per-turn taint is derived from these labels and a
policy (``check_tool_call``) blocks a privileged/egress tool call driven by
untrusted input and/or carrying sensitive data — enforced at the dispatch point
in agent_loop.py, without the loop ever inspecting model-generated argument
provenance. Do not scatter context construction elsewhere; keep it flowing
through here, or the taint accounting can be bypassed.
"""
from __future__ import annotations

import base64
import codecs
import gzip
import math
import re
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from enum import Enum


class Origin(Enum):
    """Where a piece of context came from = how much we trust it."""
    SYSTEM = "system"        # our own instructions — trusted
    USER = "user"            # the human's task — semi-trusted
    MODEL = "model"          # model-generated turn
    TOOL_RESULT = "tool_result"  # output of a tool — trust depends on the tool


# Coarse trust scores (higher = more trusted). Carried for phase 2; unused now.
TRUST = {
    Origin.SYSTEM: 100,
    Origin.USER: 60,
    Origin.MODEL: 50,
    Origin.TOOL_RESULT: 0,   # refine via TOOL_TRUST below
}

# Per-tool provenance for TOOL_RESULT items. This is the taint map phase 2 uses:
# fetch_url content is untrusted (0); local file reads are sensitive-but-local.
TOOL_TRUST = {
    "fetch_url": 0,     # UNTRUSTED — external web content, the injection channel
    "read_file": 40,    # local + potentially sensitive
    "list_files": 40,
    "send_message": 50,
}


# ===========================================================================
# PHASE 2 — information-flow-control ENFORCEMENT.
#
# Taint labels are derived on demand from the store's items (never attached to
# model-generated argument bytes — that is what makes provenance laundering a
# non-issue: reading a secret raises the label at INGEST time, so the model
# re-emitting those bytes as a fresh MODEL-origin argument cannot wash it clean).
# The decision is computed here (the seam) and applied at the tool-dispatch
# point in agent_loop.py.
# ===========================================================================

# Whether the loop ACTS on a block. run_demo flips this via --no-enforce so the
# same binary can demonstrate the exploit firing and then being blocked. The
# decision is ALWAYS computed regardless, so the verdict can audit either way.
ENFORCE = True

# Which tool RESULTS carry which taint label. UNTRUSTED is derived from the
# Phase-1 TOOL_TRUST map (score 0) so there is a single source of truth.
UNTRUSTED_SOURCES = {name for name, score in TOOL_TRUST.items() if score == 0}  # {"fetch_url"}
SENSITIVE_SOURCES = {"read_file", "list_files"}

# Egress sinks: tools with an external side effect. A call is gated when the
# current task's taint intersects the labels listed here. fetch_url is a REAL
# outbound channel (urllib), so it is a sink too — gated on SENSITIVE so a fetch
# after a sensitive read (data exfil via the URL) is caught, while ordinary
# browsing (untrusted-only taint) is not over-blocked. send_message is gated on
# both labels.
SINK_POLICY = {
    "send_message": frozenset({"UNTRUSTED", "SENSITIVE"}),
    "fetch_url": frozenset({"SENSITIVE"}),
}
# Tools known to have no external side effect — never egress-gated.
LOCAL_TOOLS = {"read_file", "list_files"}
# Any tool that is neither a known-local tool nor listed in SINK_POLICY is
# treated as an egress sink gated on ALL labels: unknown egress fails closed.
DEFAULT_SINK_LABELS = frozenset({"UNTRUSTED", "SENSITIVE"})

# PHASE 5B — INTEGRITY sinks: privileged STATE-CHANGING actions. Where egress
# sinks leak confidentiality, these threaten integrity — an injected (untrusted)
# instruction driving a destructive/state-changing action. They are gated on the
# INTEGRITY axis (UNTRUSTED taint = low integrity), not on SENSITIVE.
INTEGRITY_SINKS = {"write_file", "delete_file"}
# Targets a trusted endorsement may NEVER cover (the integrity dual of "declassify
# must not emit secret bytes"): sensitive files and anything escaping the sandbox.
_PROTECTED_TARGET = re.compile(r"(?i)(^|[\\/])secrets?\.env$|\.\.[\\/]|^[A-Za-z]:[\\/]|^/(etc|bin|usr|root)/")

# Minimum shared run length (chars) for value_taint's literal-overlap check.
_MIN_OVERLAP = 16

# Phase 3: secret-shaped patterns the trusted sanitizer redacts. Deterministic
# (not model-based) so declassification is sound and auditable.
_SECRET_PATTERNS = [
    re.compile(r"(?i)\b[a-z0-9_]*(?:key|token|password|secret|passwd|pwd|credential)[a-z0-9_]*\s*[=:]\s*\S+"),
    re.compile(r"\bsk-[A-Za-z0-9._-]{6,}"),
    re.compile(r"\bAKIA[0-9A-Z]{12,}\b"),                 # AWS access key id shape
    re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b"),          # long base64-ish / high-entropy blob
]

# ===========================================================================
# PHASE 5A — decode-aware, sound declassification.
#
# The Phase-3 sanitizer was a denylist (secret *shapes* + exact line copies);
# a transform that changed the shape smuggled the secret through declassify to an
# authorized recipient. The fix reframes sanitization from "does it look like a
# secret?" to "does any decoding of this reproduce a secret we actually hold this
# task?" — sound w.r.t. the enumerated codec set, because the secret is in context.
# ===========================================================================

# Alnum-normalized run (chars) at/above which sharing with a known secret is
# treated as recoverable and redacted. Shorter shared runs cannot reconstruct a
# secret and would risk false positives on ordinary prose.
_SECRET_FRAG = 8
# Entropy fallback for opaque credential-like tokens we do NOT hold verbatim.
# Deliberately narrow (no dots/slashes/colons, so URLs and paths are excluded) to
# keep the false-positive rate at zero.
_ENTROPY_MIN_LEN = 20
_ENTROPY_MIN_BITS = 3.6


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _alnum(s: str) -> str:
    """Lowercased alphanumerics only — the canonical form for secret comparison."""
    return re.sub(r"[^a-z0-9]", "", str(s).lower())


def _decodings(s: str) -> list:
    """Best-effort reversible decodings of `s` for comparison against known
    secrets. A decoding that matches no held secret is never acted on, so garbage
    output is harmless — this only ever *finds* an encoded secret, never invents
    one. Covers the enumerated codec battery (identity/de-space, reverse, rot13,
    url, hex, base64, gzip+base64, char-codes)."""
    raw = str(s)
    outs = []
    for cand in {raw, "".join(raw.split())}:
        outs.append(cand)
        outs.append(cand[::-1])
        try:
            outs.append(codecs.encode(cand, "rot_13"))
        except Exception:  # noqa: BLE001
            pass
        try:
            outs.append(urllib.parse.unquote(cand))
        except Exception:  # noqa: BLE001
            pass
        if len(cand) >= 8 and len(cand) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", cand):
            try:
                outs.append(bytes.fromhex(cand).decode("utf-8", "replace"))
            except Exception:  # noqa: BLE001
                pass
        if len(cand) >= 8 and re.fullmatch(r"[A-Za-z0-9+/=]+", cand):
            try:
                dec = base64.b64decode(cand + "=" * (-len(cand) % 4), validate=False)
                outs.append(dec.decode("utf-8", "replace"))
                try:
                    outs.append(gzip.decompress(dec).decode("utf-8", "replace"))
                except Exception:  # noqa: BLE001
                    pass
            except Exception:  # noqa: BLE001
                pass
    nums = re.findall(r"\d{1,4}", raw)
    if len(nums) >= 4:
        try:
            outs.append("".join(chr(int(n)) for n in nums if 0 < int(n) < 0x110000))
        except Exception:  # noqa: BLE001
            pass
    return outs


# Decision actions.
ALLOW = "allow"
BLOCK = "block"
NEEDS_APPROVAL = "needs_approval"


@dataclass
class Decision:
    action: str                       # ALLOW | BLOCK | NEEDS_APPROVAL
    reason: str = ""                  # human/audit detail — NOT fed verbatim to the model
    labels: frozenset = frozenset()   # the active taint labels at decision time


@dataclass
class ContextItem:
    role: str                       # "system" | "user" | "assistant" | "tool"
    content: str | None
    origin: Origin                  # provenance label (phase-2 seam)
    source: str | None = None       # e.g. tool name / url / filename
    tool_calls: list | None = None  # native Ollama tool_calls for assistant turns
    tool_name: str | None = None    # for tool-result messages
    extra_taint: frozenset = frozenset()  # Phase 5C: extra labels beyond source (e.g. a
    #                                        read of a file that holds untrusted content)

    def trust(self) -> int:
        """Trust score for this item. Phase 2 will consult this."""
        if self.origin is Origin.TOOL_RESULT and self.source in TOOL_TRUST:
            return TOOL_TRUST[self.source]
        return TRUST[self.origin]


class ContextStore:
    """Ordered, labeled conversation. The one place context is built."""

    def __init__(self) -> None:
        self.items: list[ContextItem] = []
        # Phase 2: egress destinations the user has explicitly authorized, and
        # an audit log of every enforcement decision (read by the verdict).
        self._approved_recipients: set[str] = set()
        self.decisions: list = []
        # Phase 3: values the trusted declassifier produced for the CURRENT task
        # (whitespace-normalized). Reset per user turn in add_user().
        self._declassified: set[str] = set()
        # Phase 5A: alnum-normalized raw inputs to declassify this task, for the
        # anti-chunking aggregate check. Reset per user turn.
        self._declassify_inputs: list[str] = []
        # Phase 5B (integrity): action targets the user pre-authorized (persist),
        # and targets a trusted endorsement cleared for the CURRENT task (per-turn).
        self._approved_actions: set[str] = set()
        self._endorsed: set[str] = set()
        # Phase 5C (second-order integrity): files whose content was written while
        # under untrusted influence. PERSISTS across turns — that persistence is the
        # laundering carrier we must track, so a later read re-raises the taint.
        self._untrusted_files: set[str] = set()

    # -- entry points (labels attach here) --------------------------------
    def add_system(self, text: str) -> None:
        self.items.append(ContextItem("system", text, Origin.SYSTEM))

    def add_user(self, text: str) -> None:
        # A new user turn starts a new task: per-turn taint and per-turn
        # declassification scope both reset here.
        self._declassified.clear()
        self._declassify_inputs.clear()
        self._endorsed.clear()
        self.items.append(ContextItem("user", text, Origin.USER))

    def add_model_turn(self, content: str | None, tool_calls: list | None = None) -> None:
        self.items.append(
            ContextItem("assistant", content or "", Origin.MODEL,
                        tool_calls=tool_calls or None)
        )

    def add_tool_result(self, tool_name: str, content: str, extra_taint=frozenset()) -> None:
        self.items.append(
            ContextItem("tool", content, Origin.TOOL_RESULT,
                        source=tool_name, tool_name=tool_name,
                        extra_taint=frozenset(extra_taint))
        )

    # -- the single choke point -------------------------------------------
    def assemble(self) -> list[dict]:
        """Convert labeled items into the exact Ollama /api/chat `messages`
        list. Provenance labels stay in the store (off the wire); phase-2
        policy reads them here before/around this conversion.
        """
        messages: list[dict] = []
        for it in self.items:
            msg: dict = {"role": it.role, "content": it.content if it.content is not None else ""}
            if it.tool_calls:
                msg["tool_calls"] = it.tool_calls
            if it.role == "tool" and it.tool_name:
                msg["tool_name"] = it.tool_name
            messages.append(msg)
        return messages

    # =====================================================================
    # PHASE 2 — enforcement. The one place a tool call is allowed / blocked.
    # =====================================================================
    def approve_recipient(self, target: str) -> None:
        """User-channel declassification: authorize an egress destination.
        Only run_demo's --approve-recipient calls this; no tool result, model
        turn, or fetched page can reach it."""
        if target:
            self._approved_recipients.add(target.strip().lower())

    def is_approved(self, target: str) -> bool:
        return bool(target) and target.strip().lower() in self._approved_recipients

    def _task_items(self) -> list:
        """Items belonging to the CURRENT task = those after the most recent
        USER turn (per-turn taint scoping). An injected page cannot forge a USER
        turn, so this boundary is attacker-controlled only in content, never in
        position — a fetch in an earlier turn does not poison a later task."""
        start = 0
        for i, it in enumerate(self.items):
            if it.origin is Origin.USER:
                start = i + 1
        return self.items[start:]

    def current_taint(self) -> set:
        """Labels the current task has been exposed to. Derived from tool
        results since the last user turn; failed (ERROR) results never taint."""
        labels: set = set()
        for it in self._task_items():
            if it.origin is not Origin.TOOL_RESULT:
                continue
            if it.content and it.content.lstrip().startswith("ERROR"):
                continue
            if it.source in UNTRUSTED_SOURCES:
                labels.add("UNTRUSTED")
            if it.source in SENSITIVE_SOURCES:
                labels.add("SENSITIVE")
            labels |= set(it.extra_taint)   # Phase 5C: laundered-file taint
        return labels

    @staticmethod
    def _overlaps(value: str, content: str) -> bool:
        """True if `value` literally contains a >= _MIN_OVERLAP run of `content`
        (whitespace/case-normalized). A cheap approximation of 'this argument
        carries bytes that came from that tool result'."""
        v = " ".join(value.lower().split())
        c = " ".join(content.lower().split())
        if not c or not v:
            return False
        if len(c) < _MIN_OVERLAP:
            return c in v
        return any(c[i:i + _MIN_OVERLAP] in v for i in range(len(c) - _MIN_OVERLAP + 1))

    def value_taint(self, args: dict) -> set:
        """Which labels' source data literally appears in the string arguments.
        Used ONLY to ESCALATE a decision (never as the sole basis for a block),
        since literal matching is trivially defeated by encoding/paraphrase —
        those cases fall through to the sound session-level check."""
        labels: set = set()
        strings = [v for v in (args or {}).values() if isinstance(v, str) and v]
        if not strings:
            return labels
        for it in self._task_items():
            if it.origin is not Origin.TOOL_RESULT or not it.content:
                continue
            if it.content.lstrip().startswith("ERROR"):
                continue
            is_untrusted = it.source in UNTRUSTED_SOURCES or "UNTRUSTED" in it.extra_taint
            is_sensitive = it.source in SENSITIVE_SOURCES or "SENSITIVE" in it.extra_taint
            if not (is_untrusted or is_sensitive):
                continue
            if any(self._overlaps(s, it.content) for s in strings):
                if is_untrusted:
                    labels.add("UNTRUSTED")
                if is_sensitive:
                    labels.add("SENSITIVE")
        return labels

    def _trusted_anchor(self, target: str) -> bool:
        """True if `target` was named by the user/system (verbatim, case-
        insensitive). Those turns are fixed before any content is fetched, so an
        injected page cannot forge an anchor."""
        t = (target or "").strip().lower()
        if not t:
            return False
        # PHASE 5A: require the target to appear as a whole whitespace-delimited token
        # (surrounding sentence punctuation stripped), not a bare substring, so
        # 'corp.com' cannot anchor merely because 'report@corp.com' was mentioned —
        # while a legit 'report@corp.com.' at a sentence end still anchors.
        for it in self.items:
            if it.origin not in (Origin.SYSTEM, Origin.USER) or not it.content:
                continue
            for raw in re.split(r"\s+", it.content.lower()):
                if raw.strip(".,;:!?\"'()[]<>") == t:
                    return True
        return False

    @staticmethod
    def _destination(name: str, args: dict) -> str:
        """The egress destination used for anchor/approval checks."""
        args = args or {}
        if name == "send_message":
            return str(args.get("recipient", ""))
        if name == "fetch_url":
            url = str(args.get("url", ""))
            return urllib.parse.urlparse(url).netloc or url
        for v in args.values():
            if isinstance(v, str):
                return v
        return ""

    # -- PHASE 3/5A: declassification (trusted sanitize + capability-by-value) --
    def _sensitive_values(self) -> set:
        """High-value secret tokens ingested from SENSITIVE sources this task: the
        RHS of KEY=VALUE / KEY: VALUE lines, plus secret-shaped tokens. Deliberately
        NOT every long word — sensitive files contain prose too — so the decode-
        aware match below closes encodings without over-redacting ordinary text."""
        vals: set = set()
        for it in self._task_items():
            if it.origin is not Origin.TOOL_RESULT or not it.content:
                continue
            if it.source not in SENSITIVE_SOURCES or it.content.lstrip().startswith("ERROR"):
                continue
            for line in it.content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"^[A-Za-z0-9_.\- ]+[=:]\s*(\S.*)$", line)
                if m:
                    vals.add(m.group(1).strip())
                for tok in re.split(r"[\s,;]+", line):
                    if any(p.search(tok) for p in _SECRET_PATTERNS) or (
                        len(tok) >= 16 and _shannon_entropy(tok) >= 3.2 and re.search(r"\d", tok)
                    ):
                        vals.add(tok)
        return {v for v in vals if len(_alnum(v)) >= _SECRET_FRAG}

    def _sanitize(self, text: str) -> str:
        """Trusted, deterministic redactor. Redacts '[REDACTED]' any span that
        (a) is a full line copied from a SENSITIVE item, (b) matches a secret
        shape, (c) DECODES (under the enumerated codec set) to — or shares a
        >=_SECRET_FRAG run with — a secret we actually hold this task, or (d) is an
        opaque high-entropy credential token. (c) is the sound core: it compares
        against the real ingested secret, so encodings cannot launder it out."""
        text = str(text)
        # (a) whole lines copied verbatim from sensitive results this task.
        for it in self._task_items():
            if it.origin is not Origin.TOOL_RESULT or not it.content:
                continue
            if it.source not in SENSITIVE_SOURCES or it.content.lstrip().startswith("ERROR"):
                continue
            for line in it.content.splitlines():
                s = line.strip()
                if len(s) >= _MIN_OVERLAP and s in text:
                    text = text.replace(s, "[REDACTED]")
        # (b) secret-shaped substrings.
        for pat in _SECRET_PATTERNS:
            text = pat.sub("[REDACTED]", text)

        # (c) PHASE 5A — decode-aware match against the secrets we hold.
        secrets = {_alnum(v) for v in self._sensitive_values()}
        secrets = {s for s in secrets if len(s) >= _SECRET_FRAG}
        if secrets:
            # (c1) whole-message: any decoding reproduces a full secret -> the message
            # smuggles it via an encoding; redact wholesale (sound, and rare for prose).
            for view in _decodings(text):
                nv = _alnum(view)
                if any(sec in nv for sec in secrets):
                    return "[REDACTED]"

            # (c2) token-wise: redact a token that decodes to, or shares a >=_SECRET_FRAG
            # run with, a held secret (covers bare values and split-across-calls chunks).
            def _tok_is_secret(tok: str) -> bool:
                for view in _decodings(tok):
                    nv = _alnum(view)
                    if not nv:
                        continue
                    for sec in secrets:
                        if sec in nv or (len(nv) >= _SECRET_FRAG and nv in sec):
                            return True
                return False

            text = re.sub(r"\S+",
                          lambda m: "[REDACTED]" if _tok_is_secret(m.group(0)) else m.group(0),
                          text)

        # (d) entropy fallback: opaque credential-like tokens we don't hold verbatim.
        def _high_entropy(tok: str) -> bool:
            return (re.fullmatch(r"[A-Za-z0-9+/_=-]{%d,}" % _ENTROPY_MIN_LEN, tok) is not None
                    and _shannon_entropy(tok) >= _ENTROPY_MIN_BITS
                    and re.search(r"[A-Za-z]", tok) and re.search(r"\d", tok))

        text = re.sub(r"\S+",
                      lambda m: "[REDACTED]" if _high_entropy(m.group(0)) else m.group(0),
                      text)
        return text

    def declassify_value(self, content: str) -> str:
        """Trusted declassification: sanitize `content`, register the sanitized
        result as sendable for the CURRENT task, and return it. Declassifying a
        secret (raw or encoded) yields '[REDACTED]', so this is not an exfil
        channel."""
        clean = self._sanitize(content)
        # PHASE 5A anti-chunking: if the union of raw declassify inputs this task
        # reconstructs a held secret, deny the chunk that completes it.
        self._declassify_inputs.append(_alnum(content))
        union = "".join(self._declassify_inputs)
        secrets = {_alnum(v) for v in self._sensitive_values() if len(_alnum(v)) >= _SECRET_FRAG}
        if any(sec in union for sec in secrets):
            clean = "[REDACTED]"
        self._declassified.add(" ".join(clean.split()))
        return clean

    @staticmethod
    def _payload(name: str, args: dict) -> str:
        """The content-bearing argument of an egress call (what actually leaves)."""
        args = args or {}
        if name == "send_message":
            return str(args.get("body", ""))
        return ""

    def _payload_declassified(self, payload: str) -> bool:
        """True only if `payload` is EXACTLY a value the trusted declassifier
        produced this task (whitespace-normalized). Capability-by-value: the
        model must send back what declassify returned, so raw/edited/encoded
        secrets cannot ride this path."""
        return " ".join(str(payload).split()) in self._declassified

    # -- PHASE 5B: integrity (endorsement, the dual of declassification) ------
    def approve_action(self, target: str) -> None:
        """User-channel endorsement: authorize a privileged action target. Dual of
        approve_recipient. Only run_demo/harness calls this; no tool result, model
        turn, or fetched page can reach it."""
        if target:
            self._approved_actions.add(str(target).strip().lower())

    def is_action_approved(self, target: str) -> bool:
        return bool(target) and str(target).strip().lower() in self._approved_actions

    @staticmethod
    def _action_target(name: str, args: dict) -> str:
        """The resource a privileged action would modify."""
        args = args or {}
        return str(args.get("path", "") or args.get("target", "") or "")

    def _is_protected_target(self, target: str) -> bool:
        """True if a target must never be reached by endorsement (sensitive file /
        sandbox escape) — the integrity dual of 'declassify can't emit secrets'."""
        t = str(target or "").strip()
        if not t:
            return True
        if _PROTECTED_TARGET.search(t.replace("\\", "/")):
            return True
        base = t.replace("\\", "/").rsplit("/", 1)[-1].lower()
        return base in {"secrets.env", "secret.env"}

    def endorse_value(self, target: str) -> str:
        """Trusted endorsement (dual of declassify_value): endorse a privileged
        action iff its target satisfies the integrity invariant — inside the
        sandbox, not a protected/sensitive file. Registers the endorsed target for
        THIS task and returns it; a protected target returns '[NOT ENDORSED]', so
        endorse cannot be abused to license tampering."""
        t = str(target or "").strip()
        if self._is_protected_target(t):
            return "[NOT ENDORSED]"
        self._endorsed.add(t.lower())
        return t

    def _action_endorsed(self, target: str) -> bool:
        return bool(target) and str(target).strip().lower() in self._endorsed

    def _check_integrity_action(self, name: str, args: dict) -> Decision:
        """Integrity gate for a privileged state-changing action. UNTRUSTED taint =
        low integrity driving the action. With no untrusted influence the user is
        driving, so allow. Under untrusted influence the action needs HIGH-integrity
        authorization; a protected target can only be reached by an explicit user
        anchor/approval, never by endorsement (default-deny is the dual of the
        confidentiality both-axis default-deny)."""
        taint = self.current_taint()
        if "UNTRUSTED" not in taint:
            return Decision(ALLOW, "no untrusted influence; privileged action is user-driven")
        active = frozenset({"UNTRUSTED"})
        target = self._action_target(name, args)
        if self._is_protected_target(target):
            if self.is_action_approved(target) or self._trusted_anchor(target):
                return Decision(NEEDS_APPROVAL,
                                f"{name} on protected {target!r} under untrusted influence", active)
            return Decision(BLOCK,
                            f"{name} on protected target {target!r} driven by untrusted content", active)
        if self._action_endorsed(target):
            return Decision(ALLOW, f"{name} on endorsed target {target!r} (safe envelope)", active)
        if self.is_action_approved(target) or self._trusted_anchor(target):
            return Decision(ALLOW, f"{name} on user-authorized target {target!r}", active)
        return Decision(NEEDS_APPROVAL,
                        f"privileged {name} on {target!r} driven by untrusted content, not endorsed", active)

    # -- PHASE 5C: second-order integrity (write-then-read laundering) --------
    @staticmethod
    def _norm_path(path: str) -> str:
        """Normalize a sandbox-relative path for the tainted-file registry."""
        p = str(path or "").strip().lower().replace("\\", "/").lstrip("/")
        if p.startswith("sandbox/"):
            p = p[len("sandbox/"):]
        return p

    def note_write_taint(self, path: str, args: dict) -> bool:
        """Called after a write_file executes. If the write happened while the task
        was under untrusted influence (its content may carry untrusted bytes), mark
        the file so a LATER read re-raises the UNTRUSTED label instead of laundering
        it into trusted-local content. Conservative (session-level) on purpose: an
        over-mark only makes a later read fail safe. Returns whether it marked."""
        if "UNTRUSTED" in self.current_taint():
            self._untrusted_files.add(self._norm_path(path))
            return True
        return False

    def is_untrusted_file(self, path: str) -> bool:
        return self._norm_path(path) in self._untrusted_files

    def read_extra_taint(self, tool_name: str, args: dict) -> frozenset:
        """Extra taint to attach to a tool result. A read of a file that holds
        untrusted content carries UNTRUSTED, closing the write-then-read launder."""
        if tool_name == "read_file" and self.is_untrusted_file((args or {}).get("path", "")):
            return frozenset({"UNTRUSTED"})
        return frozenset()

    def check_tool_call(self, name: str, args: dict) -> Decision:
        """Compute the enforcement decision for one tool call. Reads SESSION
        STATE (what this task has ingested) + literal payload overlap as an
        escalator — never the origin label of the model-generated argument
        string. Always computes the true decision; whether the loop ACTS on it
        is governed by the module-level ENFORCE flag in agent_loop."""
        if name in LOCAL_TOOLS:
            return Decision(ALLOW, "local tool, no external egress")

        # PHASE 5B: privileged state-changing actions take the integrity gate.
        if name in INTEGRITY_SINKS:
            return self._check_integrity_action(name, args)

        labels = SINK_POLICY.get(name, DEFAULT_SINK_LABELS)
        taint = self.current_taint()
        active = frozenset(taint & labels)
        if not active:
            return Decision(ALLOW, "no active taint for this sink", active)

        dest = self._destination(name, args)

        # Branch 0: the payload is a value the trusted declassifier produced this
        # task (sanitized + registered). The sink emits only bytes the sanitizer
        # produced, so the data axis is cleared — but the send still needs an
        # authorized destination (a sanitized message is not a licence to spam).
        payload = self._payload(name, args)
        if payload and self._payload_declassified(payload):
            if self.is_approved(dest) or self._trusted_anchor(dest):
                return Decision(ALLOW, f"declassified payload to authorized {dest!r}", active)
            return Decision(NEEDS_APPROVAL, f"declassified payload but {dest!r} not authorized", active)

        vt = self.value_taint(args)
        untrusted = "UNTRUSTED" in taint

        # Branch 1: sensitive bytes literally egressing while under untrusted
        # influence — the confused-deputy exfil shape. Hard block unless the
        # destination was EXPLICITLY pre-approved (a passive anchor is too weak
        # when raw secrets are in the payload).
        if untrusted and "SENSITIVE" in vt:
            if self.is_approved(dest):
                return Decision(NEEDS_APPROVAL, f"literal sensitive egress to pre-approved {dest!r}", active)
            return Decision(BLOCK, f"literal sensitive data egressing to {dest!r} under untrusted influence", active)

        # Branch 2: both untrusted AND sensitive in the task, payload not proven
        # literal. Default-deny; only explicit approval (not a passive anchor)
        # clears it — this closes 'steer the send to a recipient the user named'.
        if {"UNTRUSTED", "SENSITIVE"} <= taint:
            if self.is_approved(dest):
                return Decision(ALLOW, f"both-axis taint; {dest!r} explicitly approved", active)
            return Decision(NEEDS_APPROVAL, f"both untrusted+sensitive taint; {dest!r} not approved", active)

        # Branch 3: single-axis taint. A user-named or approved destination is
        # sufficient authorization (recovers 'summarize <url> and email bob').
        if self.is_approved(dest) or self._trusted_anchor(dest):
            return Decision(ALLOW, f"single-axis taint; {dest!r} authorized by user", active)
        return Decision(NEEDS_APPROVAL, f"single-axis taint; {dest!r} not authorized by user", active)
