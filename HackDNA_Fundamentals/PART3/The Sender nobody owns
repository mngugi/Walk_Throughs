## The sender nobody owns

# SPF Dead Include — MER-4471

## Finding

**Dead SPF include:**

`relay.driftsend.example.`

## How It Works

SPF is a **tree**, not a line. The `meridian.example` SPF record delegates to several other SPF records using `include:` mechanisms.

The relevant branch is:

```text
meridian.example
├── _spf.meridian.example
│   └── ip4 leaf
│
├── _spf.parcelpal.example
│   └── ip4 leaf
│
└── spf.mailhive.example
    └── include:relay.driftsend.example
        └── NXDOMAIN
```
---

The first two includes resolve normally to ip4 mechanisms. However, spf.mailhive.example contains another delegation:

```text
v=spf1 ip4:203.0.113.64/27 include: relay. driftsend.example -all

```
Following that, include: requires another DNS TXT lookup:

```text
dig relay.driftsend.example TXT

```
The result is:


```text
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN
;; flags: qr rd ra; QUERY: 1, ANSWER: 0

```
This confirms that:

relay.driftsend.example

does not currently exist in DNS.

Why This Is a Vulnerability

The SPF tree still contains a delegation to a hostname that no longer exists.

According to the ticket, Driftsend's contract ended on `2026-03-31,` the campaign account was closed, and the domain/name subsequently lapsed. MailHive did not remove the obsolete include: from its SPF record.

As a result, SPF evaluation of mail claiming to originate from meridian.example can still reach the obsolete Driftsend branch.

Conceptually:

```text

meridian.example
       |
       v
spf.mailhive.example
       |
       | include:
       v
relay.driftsend.example
       |
       | NXDOMAIN
       v
   DEAD BRANCH

```

The security issue is therefore a dangling SPF include.

If the abandoned hostname becomes registrable, an unauthorized party could potentially publish an SPF policy at that location and influence the SPF evaluation of the parent domain.

Evidence
1. MailHive SPF Record

Command:
```text

dig spf.mailhive.example TXT

```
Relevant response:

```text
spf.mailhive.example. 1800 IN TXT
"v=spf1 ip4:203.0.113.64/27 include:relay.driftsend.example -all"

```
This establishes the delegation to:

relay.driftsend.example
2. Dead Include

Command:

```text
dig relay.driftsend.example TXT

```
Response:

```text

;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

```
The important fields are:

```text
status: NXDOMAIN
ANSWER: 0

```
NXDOMAIN means that the queried DNS name does not exist.

The SOA record appearing in the AUTHORITY SECTION belongs to the enclosing example. zone. It does not mean that relay.driftsend.example exists.

Impact

The obsolete SPF delegation creates a dangling DNS/SPF trust relationship.

An attacker who can legitimately register the abandoned delegated name could potentially publish an SPF policy under that name and cause SPF evaluation to authorize infrastructure that was not intended to represent meridian.example.

This could be particularly relevant to phishing or invoice-fraud campaigns because SPF validation may report the message as passing for the victim domain.

### Root Cause

The apparent root cause is failure to remove an obsolete third-party SPF dependency after the vendor relationship ended.

```text
Vendor relationship ended
        |
        v
Vendor resource lapsed
        |
        v
DNS name became NXDOMAIN
        |
        v
Parent SPF record retained include:
        |
        v
Dangling SPF delegation
Remediation

```

Remove the obsolete:

```text
include:relay.driftsend.example

```

from the SPF chain.

If a replacement vendor is required, replace it with the vendor's currently authorized SPF mechanism.
Re-walk the complete SPF tree after the change.
Check all include: mechanisms for:
+ NXDOMAIN
+ obsolete vendors
+ abandoned domains
+ unexpected third-party dependencies
+ unnecessarily broad authorization

> Review other DNS-based trust relationships for similar abandoned third-party resources.
Ticket Update

MER-4471 — Dead SPF Include

Walking the SPF tree identified `spf.mailhive.example` as a delegated SPF record containing `include:relay.driftsend.example.`

A TXT lookup of relay.driftsend.example returns NXDOMAIN, confirming that the delegated hostname does not currently exist.

The finding is therefore a dangling/dead SPF include. The obsolete Driftsend delegation should be removed or replaced, followed by a complete re-walk of the SPF tree to identify any additional lapsed vendor dependencies.

Final Finding

Dead SPF include: relay.driftsend.example

DNS status: NXDOMAIN

Parent record: spf.mailhive.example

Vulnerability: Dangling/obsolete SPF include: delegation

```text
Ticket: MER-4471
``
