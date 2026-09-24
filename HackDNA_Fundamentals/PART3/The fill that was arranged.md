
# Sandwich Attack Analysis: Vertex Desk ORCA Trade

## Summary

**Attacker address:** `0x7f3ad9c41b8e5027a6f4c19d3b70e582cc41d9a6`

**First 10 characters:** `0x7f3ad9c4`

The attacker sandwiched the Vertex Desk's 40 WETH → ORCA swap in block **21594118**, using a **341 gwei** gas premium (roughly 15× the ~22 gwei paid by everyone else) to secure the positions immediately before and after the victim's trade.

---

## The Victim Trade

| Field | Value |
|---|---|
| **Block** | 21594118 |
| **Position** | 41 |
| **Sender** | `0x4d81ac9f2b7e61d0cc35a84f19e7b2065da3f7c8` |
| **Swap** | WETH → ORCA |
| **Amount in** | 40.00 WETH |
| **Amount out** | 104,880 ORCA |
| **Expected** | ~118,000 ORCA |
| **Shortfall** | ~11% worse |
| **Gas** | 22 gwei |

---

## The Sandwich

Three transactions in one block, with the two outer transactions bracketing the desk's swap:

| Position | Address | Action | Amount In | Amount Out | Gas |
|---|---|---|---:|---:|---:|
| 40 | `0x7f3ad9c4...` | WETH → ORCA (front-run) | 18.00 WETH | 51,204 ORCA | **341 gwei** |
| 41 | `0x4d81ac9f...` | WETH → ORCA (**victim**) | 40.00 WETH | 104,880 ORCA | 22 gwei |
| 42 | `0x7f3ad9c4...` | ORCA → WETH (back-run) | 51,204 ORCA | 20.61 WETH | **341 gwei** |

### How It Works

1. **Front-run (position 40):** The attacker buys ORCA using 18 WETH before the desk's order executes. This moves the pool price against the desk.
2. **Victim trade (position 41):** The desk's 40 WETH swap executes at the worsened price the attacker just created, receiving 104,880 ORCA instead of approximately 118,000 ORCA.
3. **Back-run (position 42):** The attacker sells back the 51,204 ORCA bought moments earlier, now into the demand the desk itself supplied, for 20.61 WETH.

**Result:** The attacker netted **2.61 WETH** in gross proceeds before accounting for gas and other transaction costs (18.00 WETH in → 20.61 WETH out). This is consistent with the price impact experienced by the desk, although the attacker's profit cannot be equated directly to the desk's approximately 13,000 ORCA shortfall.

---

## Why the Gas Premium Matters

The attacker paid **341 gwei** on both sandwich legs, approximately 15× the going rate (~22 gwei) paid by the other traders in the block.

This premium helped secure the required transaction ordering:

- **Front of the block:** The attacker needed to land exactly in front of the desk's swap.
- **Back of the same block:** The attacker needed to land exactly behind the desk's swap, before another trader could arbitrage the resulting price movement.

Both attacker transactions reportedly share the same transaction-hash prefix, `0xe73c...` (legs `20d1` and `20d2`), which is consistent with a coordinated operation.

> **Note:** A shared transaction-hash prefix alone does not prove that the transactions were coordinated. Full transaction hashes, sender addresses, nonce relationships, and execution traces would provide stronger evidence.

---

## Ruling Out the Decoys

Two other addresses show buy/sell activity in nearby blocks but do not fit the identified sandwich pattern:

| Address | Behavior | Why It Is Not the Attacker |
|---|---|---|
| `0xa83c15e0...` | Buys at position 06 and sells at position 71 of the same block | Ordinary gas (~26 gwei); no clearly identified victim trade between the two legs. |
| `0xb27f604c...` | Sells then buys in block 21594117 | The order is reversed. A sell-then-buy sequence does not match the identified buy-side sandwich pattern. |

Only `0x7f3ad9c4...` brackets the victim on both sides, in the correct order, with the reported gas premium that helped make the ordering possible.

---

## Answer

**Attacker address:**

`0x7f3ad9c41b8e5027a6f4c19d3b70e582cc41d9a6`

**First 10 characters:**

`0x7f3ad9c4`
