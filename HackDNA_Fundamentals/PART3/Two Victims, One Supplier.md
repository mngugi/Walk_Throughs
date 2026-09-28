
On 4 September an account with staff privileges was used to export 11,400 patient records. The account belongs to a clinician who was on leave and did not log in. There was no phishing email. Multi-factor authentication was enabled on the account and was not challenged, because the session was not created by a login: **it was created by a support agent using the assist feature in our helpdesk suite.**

**Our environment:**
- Latchkey SSO
- Tidemark Helpdesk
- Northfield Payroll
- Pinmark Analytics

We have rotated credentials across all four.

---

### 📋 Calder Freight Ltd – 8-K Style Disclosure (Filed 2026-09-10)

**Item 1.05 Material Cybersecurity Incident**

On 6 September 2026 the Company identified unauthorised activity in its operations portal. A session attributed to a dispatch manager was used to download customer contract data. The employee was travelling and their device was powered off for the duration of the session.

The Company has found no evidence of credential theft, password reuse or malware on Company devices. **The session in question did not originate from an authentication event.**

**Systems in scope of the review:**
- Latchkey SSO
- Tidemark Helpdesk
- Vantage MDM
- Trellis CRM

---

### 📡 status.latchkey.example – Service History (DNS)

**Latchkey SSO – incident history, last 90 days**

| Date | Event |
|------|-------|
| 2026-08-19 | Degraded performance, EU region – resolved 41m |
| 2026-09-02 | Scheduled maintenance, key rotation completed |
| 2026-09-15 | Elevated SAML latency – resolved 22m |

**No security incidents reported in this period.**

Latest third-party assessment published 2026-07-30: **no findings above low.**

---

### 📋 status.tidemark.example – Incident 2026-09-03

**Tidemark Helpdesk – Incident report: unauthorised access to agent tooling**

Posted 2026-09-12, updated 2026-09-14

Between 2 and 7 September an unauthorised party held a valid session in our internal agent console. The session could invoke **Assist**, the feature that lets an agent open a customer application as an end user in order to reproduce a reported problem.

**Assist sessions are created server-side and do not perform a login on the customer tenant, so they do not appear in customer authentication logs and are not subject to customer MFA policy.** They are recorded in the Tidemark agent audit log, which customers could not query until 2026-09-14.

Customers with Assist enabled should review the agent audit log for the window above.

---

### 💬 hiring: Calder Freight, Senior Platform Engineer (Forum)

Posted 3 weeks ago – Manchester, hybrid

You will own our identity and endpoint stack:
- **Latchkey SSO** across 1,100 staff
- **Vantage MDM** on the depot fleet
- **Trellis CRM** integration

Experience running a regulated logistics environment is a plus.

**Note:** we run our customer support on **Tidemark** and you would inherit that integration, including the **SCIM sync** and the **Assist grant**.

---

### 💬 r/sysadmin – "anyone else seeing session anomalies this month?" (Forum)

**u/mkane_ops – 11 Sep**

> Two of our peers in the same sector got hit in the same week and neither of them can find an initial access vector. Same story both times: a staff session that nobody logged into.

**u/harlow_infra – 11 Sep**

> We use Latchkey, Tidemark, Northfield and Pinmark. Nothing in the Latchkey logs at all, which is what is driving everyone mad.

**u/bramble_health – 12 Sep**

> We dropped Tidemark in July for an in-house desk and we are the only clinic group in our buying consortium that has not had an incident. We still run Latchkey and Northfield exactly like everyone else.

---

## Analysis

### Step 1 – Find the intersection

| Organisation | Systems |
|--------------|---------|
| **Harlow Clinic Group** | Latchkey SSO, Tidemark Helpdesk, Northfield Payroll, Pinmark Analytics |
| **Calder Freight Ltd** | Latchkey SSO, Tidemark Helpdesk, Vantage MDM, Trellis CRM |

**Intersection:** Latchkey SSO, Tidemark Helpdesk

Two candidates remain. The rest of the board must separate them.

---

### Step 2 – Eliminate Latchkey

- Latchkey's status history covers the whole window with **no security incidents**.
- Harlow's own engineer states: *"Nothing in the Latchkey logs at all."*
- Bramble Health still runs Latchkey and was **not** hit.

**Latchkey is eliminated.**

---

### Step 3 – Confirm Tidemark

Tidemark published an incident for **2–7 September**, which brackets both intrusions (4 Sep and 6 Sep).

The report describes the exact mechanism both victims could not explain:

> Assist lets an agent open a customer's application as an end user. The session is created **server-side**, performs **no login on the customer tenant**, and is therefore **absent from customer authentication logs** and **outside customer MFA policy**.

That matches:
- Harlow: session created by a support agent using the assist feature; MFA not challenged.
- Calder: session did not originate from an authentication event.

---

### Step 4 – Control group confirms

Bramble Health:
- Same identity stack as Harlow (Latchkey, Northfield).
- **Dropped Tidemark in July.**
- **Only clinic group in the consortium without an incident.**

This isolates Tidemark as the common factor.

---

## Answer

**Supplier:** Tidemark Helpdesk

**Mechanism:** The **Assist** feature creates a vendor-side impersonation session that bypasses customer authentication and MFA entirely. The session is invisible in customer logs and only recorded in Tidemark's agent audit log, which customers could not query until 2026-09-14.

---

## Key Takeaways

1. **Vendor impersonation is a second authentication plane.** You can enforce MFA on your own logins and still be bypassed by a vendor session that never authenticates against your tenant.

2. **You own the risk but cannot see it.** If the audit trail lives only with the vendor, you have blind spots in real time.

3. **Intersection alone is not enough.** Latchkey and Tidemark both appeared in both stacks; only the surrounding records (status history, forum posts, control group) separated them.

4. **The control group is the clincher.** Bramble Health dropping Tidemark while keeping everything else is the natural experiment that confirms causation.
