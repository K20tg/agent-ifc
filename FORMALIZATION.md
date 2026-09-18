# A Formal Account of the IFC Agent-Security Layer

*What the system guarantees, and why the code enforces it.*

This document is the synthesis layer over Phases 1–5C. Where the reports and tests show the
system *works*, this states the **security property** precisely and argues the implementation
**enforces** it — turning "it blocks the attacks we tried" into "it cannot leak or tamper
except through named, audited operators." It is a paper-style argument, not a machine-checked
proof; every claim cites the code that discharges it.

---

## 1. System model

The agent is a loop (`agent/agent_loop.py`) over a single labeled context store
(`agent/context.py::ContextStore`). Each iteration: assemble the model input, make one model
call, and for each requested tool call either execute it or refuse it. Two structural
invariants make the system analyzable:

- **Single ingress.** Every element the model ever sees enters through a `ContextStore.add_*`
  method and leaves through exactly one function, `assemble()`. Each element carries a
  provenance label (`Origin`) and, for tool results, the producing tool (`source`).
- **Single egress choke point.** Every tool side effect is dispatched at exactly one place in
  `agent_loop.run`, immediately after `ContextStore.check_tool_call` returns a `Decision`.
  There is no other path to a side effect.

Tools are partitioned by role:

| Tool | Role |
|---|---|
| `fetch_url` | **source** (untrusted web) and **egress sink** (real outbound) |
| `read_file`, `list_files` | **source** (sensitive-local); never egress-gated (`LOCAL_TOOLS`) |
| `send_message` | **egress sink** (confidentiality) |
| `write_file`, `delete_file` | **integrity sink** (state-changing) |
| `declassify` | trusted **downgrader** (confidentiality) |
| `endorse` | trusted **upgrader** (integrity) |

## 2. Threat model

**Assets.** (C) the contents of sensitive files (e.g. `sandbox/secrets.env`); (I) the
integrity of privileged state-changing actions.

**Adversary.** An attacker who controls (a) the full content of any page returned by
`fetch_url`, and (b) any bytes on an untrusted channel that later re-enter the agent. The
adversary’s goal is to make the agent exfiltrate an asset (C) or perform an unrequested
privileged action (I).

**Trust boundary.** `SYSTEM` and `USER` turns are trusted and fixed *before* any untrusted
content is fetched. The harness code is trusted (§6). **The LLM is *not* trusted** — see the
adversarial assumption below.

**Attacker capabilities (in scope).** Prompt injection in fetched content; provenance
laundering by re-emitting data as model output; encoding/paraphrase of secrets; steering a
send to a user-named recipient; driving a destructive action; laundering untrusted content
through a file (write-then-read), including across turns; unknown/unmodeled tools.

**Out of scope.** Path traversal to the real filesystem (blocked at the tool layer, not an
IFC claim); side channels below the tool granularity (timing, model weights); a compromised
harness or OS; covert channels using encodings outside the enumerated set (§9).

## 3. Label model

Two independent axes, each a lattice; the state is a point in their product, ordered by
subset, with **join = set union**.

- **Confidentiality (secrecy):** `PUBLIC ⊑ SENSITIVE`. `read_file`/`list_files` results are
  `SENSITIVE` (`SENSITIVE_SOURCES`).
- **Integrity:** `TRUSTED ⊒ UNTRUSTED` (i.e. `UNTRUSTED` is *low* integrity). `fetch_url`
  results are `UNTRUSTED` (`UNTRUSTED_SOURCES`, derived from the score-0 entries of the
  Phase-1 `TOOL_TRUST` map — one source of truth).

**Taint derivation (`current_taint`).** The label of the *current task* is the join of the
labels of all non-error tool results since the most recent `USER` turn (`_task_items`), plus
any per-item `extra_taint` (Phase 5C). A failed (`ERROR`) result never taints.

**Sinks and their gates.**

| Sink | Gate labels | Rule source |
|---|---|---|
| `send_message` | `{UNTRUSTED, SENSITIVE}` | `SINK_POLICY` |
| `fetch_url` | `{SENSITIVE}` | `SINK_POLICY` (outbound → exfil via URL) |
| unknown tool | `{UNTRUSTED, SENSITIVE}` | `DEFAULT_SINK_LABELS` (fail closed) |
| `write_file`, `delete_file` | `{UNTRUSTED}` | `INTEGRITY_SINKS` (integrity gate) |

## 4. The adversarial-model assumption (why this is sound despite an untrusted LLM)

> **Assumption A (black-box model).** The LLM is an arbitrary, possibly adversarial function
> of its entire context window: any value it emits — including a tool-call argument — may
> depend on *any* input it has seen this task.

This is the crux. We do **not** attempt semantic non-interference over the model’s internal
computation (impossible for a black box). Instead we treat the model as maximally mixing and
push all labeling to the **trust boundary**:

> **Invariant M (monitor soundness).** At every tool call in a task, `current_taint()` is an
> over-approximation of the join of the labels of all inputs that could have influenced that
> call.

*Why M holds:* every model-visible datum enters via a labeled `add_*` (single ingress);
`current_taint` joins the labels of all task tool-results and never lowers them within a task
(labels are add-only until a `USER` turn resets scope); `SYSTEM`/`USER` are the trusted
baseline. Under Assumption A the model’s argument bytes may depend on all of these, so their
join bounds the influence. **Implicit flows are covered for free:** because we assume maximal
mixing, we never need to trace *how* the model routed data — the task label already dominates
every route. Crucially, the decision reads *session state*, never the origin label of the
model-generated argument string, so re-emitting a secret as a fresh `MODEL`-origin value
cannot wash its label.

## 5. Security properties

Write `sink(dest, payload)` for an egress and `act(target)` for a privileged action.

> **Proposition C (confidentiality).** Under `ENFORCE`, no egress sink executes while
> `SENSITIVE ∈ current_taint()` **except** when either (i) `payload` is exactly a value
> produced by `declassify` this task *and* `dest` is authorized, or (ii) `dest` was explicitly
> pre-approved by the user. In case (i) the payload provably contains no `SENSITIVE` literal
> under the enumerated codec set (§7).

*Proof sketch.* Every egress routes through `check_tool_call` at the single dispatch point.
If `SENSITIVE` (∩ the sink’s gate) is active, the empty-taint early return is skipped and the
call reaches the branch ladder. Branch 1 hard-blocks a literal sensitive payload under
untrusted influence; Branch 2 default-denies both-axis taint unless explicitly approved;
Branch 0 admits only a `declassify`-produced payload to an authorized `dest`. No branch
returns `ALLOW` for a `SENSITIVE`-tainted sink otherwise. By Invariant M the task label bounds
the actual influence, so no un-declassified secret-derived byte reaches the sink. ∎

> **Proposition I (integrity).** Under `ENFORCE`, no privileged action executes while
> `UNTRUSTED ∈ current_taint()` **except** on a `target` that is user-anchored, user-approved
> (`approve_action`), or `endorse`d — and an `endorse`d target provably lies within the safe
> envelope (inside the sandbox, not a protected/sensitive file).

*Proof sketch.* `write_file`/`delete_file` route to `_check_integrity_action`. With no
`UNTRUSTED` taint the action is user-driven → `ALLOW`. With `UNTRUSTED` present: a protected
target hard-blocks unless the user explicitly named/approved it; otherwise the call is
`ALLOW`ed only if endorsed/anchored/approved, else default-denied. `endorse_value` returns
`[NOT ENDORSED]` for any protected target, so endorsement cannot license tampering. ∎

> **Corollary L (no laundering).** Neither property is escaped by (a) re-emitting data as
> model output (Invariant M — decisions read session state, not argument origin), nor (b)
> encoding a secret through `declassify` (§7), nor (c) writing untrusted content to a file and
> reading it back — Phase 5C’s persistent `_untrusted_files` mark re-raises `UNTRUSTED` on
> read, restoring the task label that (a)/(b) rely on.

## 6. Trusted computing base

The properties hold **iff** the following are correct. Everything else — including the LLM,
the tool bodies’ business logic, and all prompt text — is untrusted and may misbehave without
violating the guarantee:

1. `ContextStore.check_tool_call` and `_check_integrity_action` — the decision function.
2. The single dispatch/enforcement point in `agent_loop.run` (and its `declassify`/`endorse`
   interception).
3. The two trusted operators: `_sanitize` / `declassify_value` (confidentiality downgrader)
   and `endorse_value` (integrity upgrader).
4. The labeling seam: `ContextStore.add_*`, `current_taint`, `_task_items`, and the
   source/sink maps (`UNTRUSTED_SOURCES`, `SENSITIVE_SOURCES`, `SINK_POLICY`, `INTEGRITY_SINKS`,
   `DEFAULT_SINK_LABELS`).

That the LLM is *outside* this list is the entire point: the guarantee is model-independent,
which the Phase-4 eval corroborates empirically (0–100% injectability across models, 100%
defense-held on all).

## 7. Soundness of the downgraders

The two operators are what make the exceptions in §5 safe; both are deterministic and
auditable (no model in the loop).

- **`declassify` / `_sanitize`.** Reframed in Phase 5A from a shape *denylist* to a
  **decode-aware match against the secrets actually held this task** (`_sensitive_values`):
  for any decoding in the enumerated codec set (`_decodings`), if the output reproduces — or a
  token shares a `_SECRET_FRAG` run with — a held secret, it is redacted; a per-turn aggregate
  closes split-across-calls chunking. **Guarantee:** a `declassify` output contains no held
  secret recoverable under the enumerated codecs. Evidence: `bypass_harness.py` — 24/40 cells
  bypassed the old denylist, 0/40 after.
- **`endorse` / `endorse_value`.** Clears a target **iff** it satisfies the integrity
  invariant (inside the sandbox, not a protected/sensitive target per `_PROTECTED_TARGET`).
  **Guarantee:** an endorsed action stays within the safe envelope; a protected target can be
  reached only by an explicit high-integrity user anchor/approval, never by endorsement.

Both are the exact structural dual of one another (see §8), and both come with a **capability-
by-value** binding: the action the model finally issues must match, byte-for-byte, what the
trusted operator returned (`_payload_declassified`; the endorsed-target set), so an edited or
re-encoded value does not inherit the clearance.

## 8. The confidentiality / integrity duality

| | Confidentiality | Integrity |
|---|---|---|
| Dangerous label | `SENSITIVE` | `UNTRUSTED` |
| Protected event | data **leaving** a sink | action **executing** |
| Gated sinks | `send_message`, `fetch_url` | `write_file`, `delete_file` |
| Trusted operator | `declassify` (removes secrets) | `endorse` (bounds the action) |
| User channel | `approve_recipient` | `approve_action` |
| Hard-block case | literal secret egress under untrusted influence | action on a protected target under untrusted influence |
| Default-deny case | both-axis taint, unproven payload | untrusted-driven, unendorsed target |

The two halves are the same monitor instantiated on the two axes; §5’s Propositions C and I
have identical shape.

## 9. Assumptions and residual limits (delimiting the claim)

1. **Codec-relative soundness.** `declassify`’s guarantee is relative to `_decodings`’
   enumerated set plus a conservative entropy fallback. A novel bijective encoding could pass;
   the **both-axis default-deny remains the backstop** for unauthorized destinations, and
   `declassify → authorized-only` stays the sole release path.
2. **Granularity.** Confidentiality is byte/pattern-level; integrity file-taint (5C) is
   whole-file. Other persistence channels (DB rows, env vars, a network round-trip) would need
   the same mark-on-write / raise-on-read treatment.
3. **Conservative over-tainting.** 5C marks any file written under untrusted influence; this
   can over-taint, but only ever fails safe (a later read is treated as untrusted).
4. **Tool surface.** Sinks (`send_message`, `write_file`, `delete_file`) are stubs; a real
   deployment wires the same gate in front of real implementations at the same single point.
   New tools must be classified into the source/sink maps or they inherit `DEFAULT_SINK_LABELS`
   (fail-closed) — a safe default, not a silent gap.
5. **Monitor, not semantic NI.** The guarantee is a sound *label monitor* under Assumption A,
   not a proof over the model’s computation. Its strength *is* that it needs no such proof.

## 10. Phase → clause map

Each phase discharges one clause of §5; the phases are a constructive proof of the property,
not an ad-hoc pile of patches.

| Phase | Clause it establishes |
|---|---|
| 1 | the testbed + the unenforced label seam (nothing proven yet) |
| 2 | Invariant M + Proposition C’s branch ladder (per-turn taint, single choke point) |
| 3 | Proposition C exception (i): the `declassify` downgrader + capability-by-value |
| 4 | empirical corroboration that the TCB excludes the model (§6) |
| 5A | soundness of the `declassify` downgrader (§7) — codec-aware, closing laundering (b) |
| 5B | Proposition I: the integrity monitor + the `endorse` upgrader |
| 5C | Corollary L(c): persistent file taint closing write-then-read laundering |

---

*Companion documents:* `REPORT_TECHNICAL.md` (mechanism), `bypass_report.md` (5A evidence),
`PHASE5B_REPORT.md` / `PHASE5C_REPORT.md` (integrity), `eval_report.md` (multi-model data).
