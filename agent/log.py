"""Verbose, faithful logging. Everything goes to stdout AND transcript.log so
you can trace exactly where untrusted text enters and how it flows to the
privileged sink. Nothing important is truncated.
"""
import datetime
import json
import sys

from agent import config

_transcript = None
QUIET = False  # when True, emit() is silenced on stdout (used by the eval harness)


def init(path=None):
    global _transcript
    # Force UTF-8 stdout so unicode in fetched pages doesn't crash/garble logs
    # on a Windows console (default codepage is cp1252).
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    p = path or config.TRANSCRIPT_PATH
    _transcript = open(p, "w", encoding="utf-8")
    emit(f"# transcript started {datetime.datetime.now().isoformat()}")


def close():
    global _transcript
    if _transcript is not None:
        _transcript.close()
        _transcript = None


def emit(line=""):
    if not QUIET:
        print(line)
    if _transcript is not None:
        _transcript.write(line + "\n")
        _transcript.flush()


_BAR = "=" * 78
_SUB = "-" * 78


def iteration_banner(i, max_iters):
    emit()
    emit(_BAR)
    emit(f"  LOOP ITERATION {i + 1}/{max_iters}")
    emit(_BAR)


def outbound_context(messages):
    emit()
    emit(">>> FULL CONTEXT SENT TO MODEL (exact model input, nothing hidden):")
    emit(json.dumps(messages, indent=2, ensure_ascii=False))


def model_reply(reply):
    emit()
    emit("<<< MODEL REPLY:")
    if reply.content:
        emit("    content: " + reply.content.replace("\n", "\n             "))
    if reply.tool_calls:
        names = ", ".join(tc.name for tc in reply.tool_calls)
        emit(f"    tool_calls requested: [{names}]")
    else:
        emit("    tool_calls requested: (none) -> this is the final answer")


def tool_call(name, args):
    emit()
    emit(f"  -> TOOL CALL: {name}")
    emit(f"     args: {json.dumps(args, ensure_ascii=False)}")


def tool_result(name, result, untrusted=False):
    flag = "   <<< UNTRUSTED INPUT ENTERS THE CONTEXT HERE" if untrusted else ""
    emit(f"  <- RESULT from {name}:{flag}")
    text = result if len(result) <= 20000 else result[:20000] + "\n... [truncated in log]"
    for line in (text.splitlines() or [""]):
        emit("     | " + line)


def blocked(name, decision, enforced=True):
    verb = "BLOCKED" if enforced else "WOULD BLOCK (enforcement off — allowing to demo the attack)"
    emit()
    emit(f"  [IFC] {verb}: {name}  action={decision.action}")
    if getattr(decision, "labels", None):
        emit(f"        active taint: {sorted(decision.labels)}")
    emit(f"        reason (audit only, NOT shown to the model): {decision.reason}")
