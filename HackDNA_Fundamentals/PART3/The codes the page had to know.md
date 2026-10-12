
## The codes the page had to know

# The Codes the Page Had to Know

**Category:** Security Fundamentals  
**Difficulty:** Easy  
**Estimated Time:** ~3 minutes  
**Reward:** +10 XP

## Mission Briefing

Brightloom's checkout checks your discount code in the browser before it bothers the server, so that a customer who mistypes one gets told immediately.

To do that, it has to know every code, and to know every code, it has to be sent every code.

The banner advertises one of them. The page is carrying five, with their dates and their percentages, and one of them is live today and was never meant to leave the warehouse.

**Your mission:** Identify the discount code that works today but was never advertised.

## Investigate

**Target URL:** https://shop.brightloom.example/checkout

### Page Source

```html
<h1>Checkout</h1>
<p>Brightloom - basket, 3 items, 84.00</p>
<p>Autumn sale: use AUTUMN15 for 15% off until 31 October</p>
<p>Discount code</p>
<input name="voucher_code" value="">
<button>Apply</button>

<!-- Client-side prefilter so an obviously dead code never reaches /api/vouchers.
     Catalogue is rendered from the same table the API reads, dates inclusive.
     Keep it in sync or customers get told a live code is invalid. -->

<input name="today" value="2026-10-12" style="display:none">

<input name="voucher_catalogue" value="SPRING10|10|2026-03-01|2026-06-30;WELCOME5|5|2026-01-01|2027-01-01;AUTUMN15|15|2026-09-01|2026-10-31;YULE30|30|2026-12-01|2026-12-26;STAFF40|40|2026-01-01|2027-01-01" style="display:none">

<!-- BILL-2209: the API re-checks eligibility for customer codes against the order.
     Codes on the staff list are accepted on the code alone, because the handhelds
     in store have no customer to check against. Do not ship the staff list to the web client. -->

<input name="basket_total" value="84.00" style="display:none">
<input name="customer_type" value="returning" style="display:none">

<p>Delivery: standard, 3 to 5 working days</p>
<button>Pay 84.00</button>
<a href="/help/discount-codes">Discount code terms</a>
```

## Your Answer

**Code that works today and was never advertised:** `STAFF40`

## Analysis

1. **Identify the current date:** The page specifies `2026-10-12`.
2. **Inspect the voucher catalogue:** Five discount codes are exposed in the hidden `voucher_catalogue` field.
3. **Check the validity dates:** `STAFF40` is valid from `2026-01-01` to `2027-01-01`, so it is active on the specified date.
4. **Identify the intended audience:** The source comment explicitly identifies `STAFF40` as a staff-list code.
5. **Confirm the exposure:** The source comment says the staff list must not be shipped to the web client, yet the hidden catalogue contains `STAFF40`.

**Security finding:** The checkout page exposes an internal staff discount code through client-side HTML. Hiding the field with `display:none` does not protect its contents. A user can inspect the page source or browser developer tools to discover it.

**Recommended remediation:** Keep staff-only voucher codes on the server. Validate the customer's eligibility, voucher status, and order conditions on the server before applying any discount.

## How It Works

The hidden `voucher_catalogue` field carries all five codes with their validity windows, and the hidden `today` field says `2026-10-12`, so no guessing is needed.

`SPRING10` ended on 30 June. `YULE30` does not begin until 1 December. `AUTUMN15` is live, and it is also printed in the banner at the top of the page, so it is not a finding.

`WELCOME5` runs all year, but the page states `customer_type` is `returning`. That leaves `STAFF40`, valid from 1 January to 1 January of the following year, offering forty percent off, and mentioned nowhere a customer would ever see.

The second comment is the reason it matters. The API re-checks eligibility for customer codes against the order, but codes on the staff list are accepted on the code alone, because the in-store handhelds have no customer record to check against.

So the one code in this list with no server-side eligibility check is the one worth forty percent, and the same comment says it should not be shipped to the web client at all.

The prefilter is a reasonable feature built on an impossible requirement: validating input in the browser means shipping the data you validate against. Anything a page can check, a page has been told.
