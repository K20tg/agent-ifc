# Phase 5C — Second-order integrity (write-then-read laundering)

**Status:** implemented + tested. Closes the last structural gap: untrusted content that
is *laundered through the filesystem* to shed its provenance.

---

## 1. The attack

First-order taint tracks a tool result's provenance *at ingest*. But provenance can be
laundered through a **second-order** path:

1. `fetch_url` pulls attacker-controlled text → **UNTRUSTED**.
2. `write_file("notes.txt", …that text…)` — allowed, because the user asked to "save the
   page to notes.txt" (a user-anchored target passes the Phase-5B integrity gate).
3. Later — often in a **new turn**, after the per-turn taint has reset — `read_file("notes.txt")`
   returns that same attacker text, now labeled **SENSITIVE (trusted-local)** instead of
   UNTRUSTED.

The untrusted instructions have been "washed" into a trusted-looking channel. A subsequent
egress would see only SENSITIVE (single-axis) and could be released to a user-anchored
destination — the injection escapes the confidentiality *and* first-order-integrity gates.

## 2. The fix — persistent file taint that re-raises on read

Track the integrity of file **content**, not just of live tool results:

- **`_untrusted_files`** — a set of file paths whose content was written while the task was
  under untrusted influence. It **persists across user turns** (the per-turn reset does *not*
  clear it) — that persistence is exactly the laundering carrier we must remember.
- **`note_write_taint(path, args)`** — called by `agent_loop` after a `write_file` executes;
  if `UNTRUSTED ∈ current_taint()` at write time, the file is marked. Conservative
  (session-level) by design: an over-mark only makes a later read fail *safe*.
- **`read_extra_taint("read_file", args)`** — when a marked file is read, the result item
  carries an **`extra_taint = {UNTRUSTED}`** beyond its `read_file`→SENSITIVE source label.
- **`current_taint()` / `value_taint()`** now fold in each item's `extra_taint`, so a read of
  a laundered file re-raises **UNTRUSTED** into the task. The existing branches then apply
  unchanged: a laundered read that also touches a real secret becomes **both-axis default-
  deny**; a laundered egress whose payload literally carries the content hits the **Branch-1
  hard block**.

Net: writing untrusted bytes to a file and reading them back no longer sheds the UNTRUSTED
label — the confused-deputy-through-the-filesystem is closed, across turns.

## 3. What was added

| File | Change |
|---|---|
| `agent/context.py` | `ContextItem.extra_taint`; `add_tool_result(..., extra_taint)`; `current_taint`/`value_taint` fold in `extra_taint`; `_untrusted_files` (persistent); `note_write_taint`, `is_untrusted_file`, `read_extra_taint`, `_norm_path` |
| `agent/agent_loop.py` | on `read_file`, attach `read_extra_taint`; on a successful `write_file`, `note_write_taint` |
| `webapp.py` | trace shows the re-raised `extra_taint` label |
| `tests/test_secondorder.py` | **15 offline checks** |

## 4. Validation

`tests/test_secondorder.py` — **15/15 pass:**
- write-under-influence marks the file; a later (new-turn) read re-raises UNTRUSTED and the
  laundered egress is **gated, not silently allowed**;
- a file written with **no** untrusted influence is **not** tainted, and reading it stays
  clean (no false positive) — an ordinary read to a user-named recipient is still ALLOW;
- the taint mark **persists across turns**;
- path normalization (sandbox prefix / leading slash / case);
- `read_extra_taint` applies only to `read_file`;
- a laundered read alongside a real secret correctly becomes **both-axis default-deny**.

**No regression:** `test_ifc` (24) + `test_bypass` (19) + `test_integrity` (14) +
`test_secondorder` (15) = **72 offline checks, all green.**

## 5. Honest residual limits

- Marking is **conservative** (any write under untrusted influence taints the file), so a
  write of purely user-authored content that merely *coincides* with an untrusted fetch in
  the same task will over-mark. Over-marking only ever fails safe (a later read is treated as
  untrusted); it never lets a real laundered flow through.
- Taint is tracked at **whole-file** granularity and only for this project's `write_file` /
  `read_file`. Other persistence channels (a DB row, an env var, an outbound-then-inbound
  network round-trip) would need the same mark-on-write / raise-on-read treatment.
- As throughout, this is a **harness-enforced** property independent of the model, not a
  claim the model won't try to launder.
