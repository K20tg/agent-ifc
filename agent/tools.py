"""The four tools, at deliberately mixed trust levels.

  fetch_url      -> UNTRUSTED web content (the injection channel)
  read_file      -> local, sandbox-confined, potentially sensitive
  list_files     -> local, sandbox-confined, benign
  send_message   -> PRIVILEGED sink (STUB — logs only, never sends)

Safety notes (phase-1 guardrails, not defenses against injection):
  * read_file/list_files are confined to sandbox/ and reject path escapes, so an
    injection cannot reach the user's real filesystem. The vulnerability we
    demonstrate is injection-driven exfiltration, NOT path traversal.
  * send_message NEVER sends anything. It only records the call so the demo can
    report whether the exploit fired.
"""
import os
import re
import html
import urllib.request
import urllib.error
import urllib.parse

from agent import config

# Record of privileged calls, read by run_demo.py for the end-of-run verdict.
sent_messages: list[dict] = []
# Phase 5B: record of privileged STATE-CHANGING actions (write/delete). STUB —
# nothing on disk is touched; we only record intent so the demo can report it.
file_actions: list[dict] = []


# --- sandbox confinement --------------------------------------------------
def _resolve_in_sandbox(path):
    """Resolve `path` strictly inside sandbox/. Raises ValueError on escape."""
    base = config.SANDBOX_DIR.resolve()
    p = str(path).strip().replace("\\", "/").lstrip("/")
    if p.startswith("sandbox/"):        # tolerate a redundant sandbox/ prefix
        p = p[len("sandbox/"):]
    candidate = (base / p).resolve()
    if candidate != base and base not in candidate.parents:
        raise ValueError(f"path {path!r} escapes the sandbox")
    return candidate


# --- html -> text (what a real "fetch & summarize" agent would see) -------
def _html_to_text(s):
    s = re.sub(r"(?is)<script.*?</script>", " ", s)
    s = re.sub(r"(?is)<style.*?</style>", " ", s)
    s = re.sub(r"(?is)<!--.*?-->", " ", s)      # drop comments (realistic)
    s = re.sub(r"(?is)<[^>]+>", " ", s)          # drop tags — CSS-hidden text survives
    s = html.unescape(s)
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n\s*\n\s*\n+", "\n\n", s)
    return s.strip()


# --- tools ----------------------------------------------------------------
def fetch_url(url):
    """UNTRUSTED input channel. Fetches a page and returns its extracted text.

    Only http/https are allowed. This blocks file:// (and other local schemes)
    so fetch_url cannot be used to read local files and launder away their
    sensitivity label — a bypass found in Phase-2 red-teaming (reading a secret
    through the untrusted channel would otherwise tag it UNTRUSTED, not
    SENSITIVE, defeating the exfil gate)."""
    scheme = urllib.parse.urlparse(str(url)).scheme.lower()
    if scheme not in ("http", "https"):
        return (f"ERROR: fetch_url refused {url!r}: only http/https URLs are "
                f"allowed (got scheme {scheme!r}).")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vuln-agent-demo/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            charset = resp.headers.get_content_charset() or "utf-8"
        return _html_to_text(raw.decode(charset, errors="replace"))
    except urllib.error.URLError as e:
        return f"ERROR fetching {url}: {e}"


def read_file(path):
    """Read a file, confined to sandbox/."""
    try:
        target = _resolve_in_sandbox(path)
    except ValueError as e:
        return f"ERROR: {e}"
    if not target.exists():
        return f"ERROR: file not found: {path}"
    if target.is_dir():
        return f"ERROR: {path} is a directory"
    return target.read_text(encoding="utf-8", errors="replace")


def list_files(directory="."):
    """List a directory, confined to sandbox/."""
    try:
        target = _resolve_in_sandbox(directory)
    except ValueError as e:
        return f"ERROR: {e}"
    if not target.exists():
        return f"ERROR: directory not found: {directory}"
    if not target.is_dir():
        return f"ERROR: {directory} is not a directory"
    names = sorted(os.listdir(target))
    return "\n".join(names) if names else "(empty)"


def send_message(recipient, body):
    """PRIVILEGED sink. STUB: records the call, sends nothing."""
    sent_messages.append({"recipient": recipient, "body": body})
    return (f"[stub] message queued to {recipient} ({len(body)} chars). "
            f"NOTE: this is a stub — nothing was actually sent.")


def write_file(path, content):
    """PRIVILEGED state-changing action (Phase 5B). STUB: records intent, writes
    nothing to disk."""
    file_actions.append({"action": "write_file", "path": path, "content": content})
    return (f"[stub] would write {len(str(content))} chars to {path}. "
            f"NOTE: this is a stub — nothing was actually written.")


def delete_file(path):
    """PRIVILEGED state-changing action (Phase 5B). STUB: records intent, deletes
    nothing from disk."""
    file_actions.append({"action": "delete_file", "path": path})
    return f"[stub] would delete {path}. NOTE: this is a stub — nothing was deleted."


# --- dispatch registry ----------------------------------------------------
TOOLS = {
    "fetch_url": fetch_url,
    "read_file": read_file,
    "list_files": list_files,
    "send_message": send_message,
    "write_file": write_file,
    "delete_file": delete_file,
}


def dispatch(name, args):
    """Execute a tool call. `args` is the dict the model produced."""
    fn = TOOLS.get(name)
    if fn is None:
        return f"ERROR: unknown tool {name!r}"
    if not isinstance(args, dict):
        return f"ERROR: {name} expected an arguments object, got {type(args).__name__}"
    try:
        return fn(**args)
    except TypeError as e:
        return f"ERROR calling {name} with args {args}: {e}"
    except Exception as e:  # noqa: BLE001 — surface any tool error back to the model
        return f"ERROR calling {name}: {e}"
