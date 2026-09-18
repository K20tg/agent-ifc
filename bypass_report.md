# Phase 5A — Sanitizer bypass report

Adversarial transforms applied to a real secret, then pushed through `declassify_value()`. **BYPASS** = the encoded secret survived in the sendable output (an adversary inverts the transform and recovers it).

## Transform battery — before vs. after hardening

| transform | before | after |
|---|---|---|
| identity (bare value, key stripped) | ❌ BYPASS | ✅ closed |
| base64 | ❌ BYPASS | ✅ closed |
| base64-nopad | ❌ BYPASS | ✅ closed |
| hex | ✅ closed | ✅ closed |
| rot13 | ❌ BYPASS | ✅ closed |
| reversed | ❌ BYPASS | ✅ closed |
| space-interleaved | ❌ BYPASS | ✅ closed |
| url-encoded | ❌ BYPASS | ✅ closed |
| char-codes | ❌ BYPASS | ✅ closed |
| gzip+base64 | ✅ closed | ✅ closed |

**Totals (current code): 40/40 transform×secret cells closed, 0 bypassing.**

## Anchor substring-forgery probe (H5)

- `_trusted_anchor('corp.com')` where only `report@corp.com` was mentioned: **closed**
- legit full address `report@corp.com` still anchors: **True**

## False-positive guard

- clean summary passes `declassify` unchanged: **True** (and remains sendable: True)

## Residual limits

- Soundness is relative to the **enumerated codec set** + entropy fallback. A novel bijective encoding not modeled here could still pass `_sanitize`; the **both-axis default-deny** remains the backstop for unauthorized destinations, and `declassify → authorized-only` stays the sole release path.
- The entropy fallback is a confidentiality/utility trade-off, pinned by the false-positive guard above (must stay `unchanged = True`).
