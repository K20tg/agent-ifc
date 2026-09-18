"""The raw agent loop. Readable top-to-bottom; no abstraction hiding the steps.

Per iteration:
  1. assemble the exact context (single choke point in context.py)
  2. log it verbatim
  3. one model call
  4. record the model's turn
  5. if no tool calls -> that's the final answer, stop
  6. else execute each tool, log it, feed the labeled result back, repeat
"""
from agent import llm, tools, log, context


def _deny(name, args, decision):
    """Default approver for NEEDS_APPROVAL decisions: no human present -> deny."""
    return False


def run(store, tool_schemas, max_iters, approver=None):
    """Drive the conversation to completion (or the iteration cap).

    Returns the model's final text answer, or None if the cap was hit.

    Phase 2: before each tool executes, store.check_tool_call() decides
    allow/block/needs-approval from the current task's taint. This is the only
    place tool side effects happen, so it is a complete egress choke point.
    """
    if approver is None:
        approver = _deny

    for i in range(max_iters):
        log.iteration_banner(i, max_iters)

        messages = store.assemble()          # 1. exact model input
        log.outbound_context(messages)        # 2. dump it, nothing hidden

        reply = llm.call_model(messages, tool_schemas)   # 3. one model call
        log.model_reply(reply)

        raw_calls = [tc.raw for tc in reply.tool_calls]
        store.add_model_turn(reply.content, raw_calls or None)   # 4. record turn

        if not reply.tool_calls:             # 5. no tools -> final answer
            return reply.content

        for tc in reply.tool_calls:          # 6. execute each requested tool
            log.tool_call(tc.name, tc.args)

            # PHASE 3: declassify is a TRUSTED framework op (sanitize + register),
            # not an external side-effecting tool. It is always allowed and never
            # dispatched through tools.py; its sanitized output is registered so a
            # subsequent send can pass the policy.
            if tc.name == "declassify":
                clean = store.declassify_value((tc.args or {}).get("content", ""))
                log.tool_result(tc.name, clean)
                store.add_tool_result(tc.name, clean)
                continue

            # PHASE 5B: endorse is the integrity dual of declassify — a trusted
            # framework op that clears a privileged action's target iff it is within
            # the safe envelope. Always allowed; its result is registered so a
            # subsequent write_file/delete_file on that target can pass the policy.
            if tc.name == "endorse":
                endorsed = store.endorse_value((tc.args or {}).get("target", ""))
                log.tool_result(tc.name, endorsed)
                store.add_tool_result(tc.name, endorsed)
                continue

            # --- PHASE 2: information-flow-control enforcement --------------
            decision = store.check_tool_call(tc.name, tc.args)
            store.decisions.append((tc.name, decision))
            if decision.action == context.NEEDS_APPROVAL and approver(tc.name, tc.args, decision):
                decision = context.Decision(context.ALLOW, "approved by human")
            if decision.action != context.ALLOW:
                log.blocked(tc.name, decision, enforced=context.ENFORCE)
                if context.ENFORCE:
                    # Feed a GENERIC refusal back (no branch/taint detail = no
                    # oracle for the attacker to tune the payload against).
                    store.add_tool_result(
                        tc.name,
                        "[IFC BLOCK] This send was refused by the information-flow "
                        "policy because the message may contain sensitive data. To "
                        "proceed: (1) call declassify with content set to your message "
                        "body; (2) then call send_message again with the SAME recipient "
                        "and body set to EXACTLY the text declassify returned. Do this now.",
                    )
                    continue
                # Enforcement OFF: let it through to DEMONSTRATE the attack.
            # ---------------------------------------------------------------

            result = tools.dispatch(tc.name, tc.args)
            # PHASE 5C: a read of a file that holds untrusted content re-raises the
            # UNTRUSTED label, so write-then-read cannot launder provenance.
            extra = store.read_extra_taint(tc.name, tc.args)
            log.tool_result(tc.name, result,
                            untrusted=(tc.name in context.UNTRUSTED_SOURCES or "UNTRUSTED" in extra))
            store.add_tool_result(tc.name, result, extra_taint=extra)   # labeled -> back into context
            # PHASE 5C: a write performed under untrusted influence taints the file
            # for any later read (persists across turns).
            if tc.name == "write_file" and not str(result).lstrip().startswith("ERROR"):
                store.note_write_taint((tc.args or {}).get("path", ""), tc.args)

    log.emit()
    log.emit("[reached max iterations without a final answer]")
    return None
