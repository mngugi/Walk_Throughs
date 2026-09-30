
# JWT Delegation Forensics — Incident Write-Up

**Token type:** RS256-signed JWT (JWS, not encrypted)
**Issuer:** `https://sso.harbourline.example`
**Audience:** `https://payments.harbourline.example`
**Verdict:** ✅ Token is genuine. ❌ Logging/attribution is broken.

---

How it works
The claim is act, short for actor, and it is the standard way to say this token was issued through delegation. sub stays as the person whose authority is being used, d.okonkwo, and act records who is actually using it: agent.7741, a support agent, via console.harbourline.example. The AMR claim says delegation rather than pwd or MFA, which is the second tell. Nothing here is forged. The signature is valid, the token is exactly what the single sign-on service minted, and the payments API was right to honour it. The bug is on the logging side. The audit trail wrote down sub and stopped, so a delegated action from a support console was recorded as the finance director personally approving a refund at three in the morning. Every control downstream then behaved as if a director had acted: no second approver, no out-of-hours review, no anomaly on the account. Delegation is a feature worth having, and support teams genuinely need it. Recording both identities everywhere the first one appears is not optional.

---

## 1. Summary

A delegated JWT was presented to the payments API. The token was **valid, correctly signed, and correctly honored**. The defect is **not** in authentication or authorization — it is in **audit attribution**.

A support agent acting on behalf of a finance director was recorded as the **finance director personally acting**. Every downstream control that keyed off `sub` alone was therefore bypassed.

---

## 2. Decoded Token

### Header

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "sso-2026-07"
}
```

### Payload

```json
{
  "iss": "https://sso.harbourline.example",
  "aud": "https://payments.harbourline.example",
  "sub": "d.okonkwo",
  "name": "Dele Okonkwo",
  "roles": ["finance.director", "payments.approve"],
  "act": {
    "sub": "agent.7741",
    "roles": ["support.agent"],
    "via": "console.harbourline.example"
  },
  "sid": "4f1c9ab2",
  "amr": ["delegation"],
  "iat": 1790132910,
  "exp": 1790136510
}
```

### Timestamps (UTC)

| Claim | Value | Meaning |
|---|---|---|
| `iat` | 1790132910 | 2026-09-22 20:28:30 |
| `exp` | 1790136510 | 2026-09-22 21:28:30 |

**Lifetime:** 1 hour.

---

## 3. Identity Model

A delegated token carries **two identities**. Both must be preserved.

| Claim | Role | Value |
|---|---|---|
| `sub` | **Subject** — whose authority is represented | `d.okonkwo` |
| `act.sub` | **Actor** — who is *really* performing the action | `agent.7741` |
| `act.via` | Client used by the actor | `console.harbourline.example` |
| `amr` | Auth method — `delegation` (not `pwd`/`mfa`) | `["delegation"]` |

> **`sub` is who you're allowed to be. `act.sub` is who you actually are right now.**

---

## 4. What Was Correct

- ✅ Signature valid (RS256, `kid` = `sso-2026-07`).
- ✅ `iss` / `aud` / `exp` all consistent.
- ✅ Token is exactly what the SSO service minted — **nothing forged**.
- ✅ Payments API was **right** to honor it.

---

## 5. The Defect — Attribution Collapse

The audit trail wrote down `sub` and **stopped**.

```text
Recorded:  "Finance director approved a refund at 03:00"
Truth:     "Support agent (agent.7741) acting on behalf of the finance
            director approved a refund at 03:00, via support console."
```

### Downstream blast radius

| Control | Should have done | Actually did |
|---|---|---|
| Second approver | Trigger on delegated high-value action | Skipped — "director approved" |
| Out-of-hours review | Flag 03:00 activity | No flag — directors are trusted |
| Anomaly detection | Alert — agent wielding `payments.approve` | Nothing — account looked normal |

---

## 6. Root Cause

> The bug is on the **logging side**.

Any system that treats `sub` as the *complete* story will:
1. Over-attribute actions to a high-privilege principal.
2. Silently bypass controls scoped to "who is acting."
3. Destroy the delegation audit trail that RFC 8693 provides.

---

## 7. The Law

> **Record both identities everywhere the first one appears.**

Delegation is a feature worth having. Support teams genuinely need it.
**Recording the full identity pair is not optional.**

---

## 8. Required Practices

1. **Atomic pair.** Every audit event carrying `sub` MUST also carry `act` (and the full chain).
2. **Authorize on the actor.** Evaluate `act.sub` — hold it to the *stricter* of the two identities.
3. **Preserve the chain.** `act` can nest (`act.act.sub`); never flatten multi-hop delegation.
4. **Treat delegation as a risk signal.** Presence of `act` / `amr: ["delegation"]` feeds risk engines.
5. **Separate the two roles.**
   - **Authorization** → uses `sub` for authority.
   - **Attribution** → uses `act.sub` for accountability.
   - Never collapse them.

---

## 9. Detection Rule

**Flag any audit record where a delegated token was recorded as a direct action.**

```sql
-- Pseudo-detection
SELECT *
FROM audit_events
WHERE token_act IS NULL
  AND token_amr CONTAINS 'delegation';
```

Or, positively framed:

> **Any log line containing a `sub` from a delegated token must also contain its `act`.**
> Absence of `act` on a delegated token = attribution failure.

---

## 10. One-Line Takeaway

> Standards like RFC 8693 give you `act` precisely so accountability survives delegation.
> The vulnerability only appears when a downstream system assumes `sub` is the whole story.
> **Log both. Authorize carefully. Never let convenience overwrite the second one.**
