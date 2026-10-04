
# Daily Hack #108 : "First Blood" Solution

## Answer

> **The card the money is landing on is `7712`.**

---

## How the pattern was found

The briefing says the refund total rose 11% with no matching rise in returns, and that every row looks legitimate. The trick is that the fraud isn't in the *amounts* or the *notes* — it's in the **refund destination card**.

### Step 1: Filter by the `phone` channel

The challenge already gives us the filter `channel: phone`, showing **14 of 28 events**. The other 14 are `in_store` and `web`. Focusing on the phone channel exposes the anomaly.

### Step 2: Look at `refund_last4` vs `paid_last4`

In a normal refund, the money should go back to the **same card the customer paid with** (`refund_last4` should equal `paid_last4`).

Looking at the phone events:

| Operator | Refund last4 | Count |
|---|---|---|
| **l.varga** | **7712** | 10 refunds |
| p.nsimba | 8827 / 3391 | 3 refunds |

Almost every one of `l.varga`'s refunds sends money to the card ending **7712**, regardless of which card the customer originally paid with:

- Sowande paid with `8104` → refunded to `7712`
- Hollis paid with `3391` → refunded to `7712`
- Iqbal paid with `9037` → refunded to `7712`
- Marchetti paid with `2265` → refunded to `7712`
- Whitlock paid with `5518` → refunded to `7712`
- Stavros paid with `6741` → refunded to `7712`
- Amara paid with `4013` → refunded to `7712`
- Kowalczyk paid with `1902` → refunded to `7712`
- Brennan paid with `3874` → refunded to `7712`
- Osei paid with `7449` → refunded to `7712`
- Devereux paid with `6188` → refunded to `7712`

That's **11 refunds to card `7712`** from 11 different customers who paid with 11 different cards.

### Step 3: Contrast with the clean operator

`p.nsimba`'s refunds behave normally:

- Duarte paid with `3306` → refunded to `8827` (note says *"card expired, replacement provided"* — plausible)
- Hollis paid with `3391` → refunded to `3391` (same card — normal)

### Step 4: The cover story

Every one of `l.varga`'s suspicious refunds carries the note:

> **" original card declined refund"**

This is the "plausible note" that makes each row look legitimate in isolation. But the note is being used as a blanket excuse to redirect every refund to a single attacker-controlled card.

---

## Conclusion

Operator **`l.varga`** is the insider diverting refunds. The money is leaving through the phone channel and landing on the card ending in:

## How it works
Thirteen rows have a refund_last4 that does not match the paid_last4, and eleven of them land on the same card: 7712. Those eleven span eleven different customers who bought with eleven different cards, all processed by l.varga on the phone channel, all between 178 and 256, and all carrying the identical note: original card declined refund. A card that genuinely cannot accept a refund is a real thing, and it happens a few times a month. It does not happen to eleven unrelated people in four days, and when it does, the replacement card is the customer's, not the same one every time. The amounts are the second tell: each sits just under the 260 threshold where a supervisor countersignature kicks in, and none is round. Two patterns nearby are innocent and worth separating. p.nsimba redirects two refunds to 8827, but both belong to the same customer, Duarte, and the note says the card expired, which is one customer with one replacement card. And 7712 appears once as a paid_last4 on an in-store refund for Okafor that went back to the card that paid, which is what makes a naive search on 7712 return a row that proves nothing. The fraud is not any single transaction. It is the convergence.

```text
7712
