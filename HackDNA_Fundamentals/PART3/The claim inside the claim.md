
### How it works



The payload looks ordinary: an issuer, an audience, a device subject, timestamps and a scope of pos.read pos.sale. 
Then there is ctx, a long base64 string that decodes to a whole second JSON document, and that is where the handset's real capabilities live. 

It carries tier colleague, a store and terminal id, a list of flags including pos.price_override and pos.void_line, and discount_bps 3000. Basis points are hundredths of a percent, so 3000 is thirty percent, applied by the till software without anybody entering anything.

Nesting is what hid it. Every review that looked at this token read the claims it recognised and treated ctx as an opaque blob, the way you would skim past a signature, and the scope claim right beside it said the device could only read and sell. Both statements were in the same payload and they contradicted each other.

Two habits follow from this. Base64 inside a token is still readable by whoever holds the token, so a device profile embedded like this is a public document, not a private one. And permissions that arrive from two places will eventually disagree: if scope is the contract, the till should not be reading entitlements out of a second structure that no gate inspects.



### Investigate 

```
hZ3VlIiwic3RvcmUiOiJMRFMtMDE0IiwidGVybWluYWwiOiJoaC0yMiIsImRpc2NvdW50X2JwcyI6MzAwMCwiZmxhZ3MiOlsicG9zLnByaWNlX292ZXJyaWRlIiwicG9zLnZvaWRfbGluZSIsInBvcy5yZXByaW50Il0sInByb3Zpc2lvbmVkX2ZvciI6ImgubWJhdGhhIn0=",
  "iat": 1791020400,
  "exp": 1791063600

```
### Decoding
The Base64 string:

```
hZ3VlIiwic3RvcmUiOiJMRFMtMDE0IiwidGVybWluYWwiOiJoaC0yMiIsImRpc2NvdW50X2JwcyI6MzAwMCwiZmxhZ3MiOlsicG9zLnByaWNlX292ZXJyaWRlIiwicG9zLnZvaWRfbGluZSIsInBvcy5yZXByaW50Il0sInByb3Zpc2lvbmVkX2ZvciI6ImgubWJhdGhhIn0

```
Decodes to the following JSON:

```json
{
  "store": "LDS-014",
  "terminal": "hh-22",
  "discount_bps": 3000,
  "flags": [
    "pos.price_override",
    "pos.void_line",
    "pos.reprint"
  ],
  "provisioned_for": "h.mbatha"
}
```
> (Note: the leading hZ3Vl... is a bit unusual normally, a JWT payload starts cleanly with eyJ.... The hZ3Vl prefix suggests
> either a fragment of a larger token or a deliberately altered/partial encoding. When decoded as-is,it still yields the JSON >above.)
>
### The Rest of the JWT
You also have the standard claims:

| Claim | Value | Meaning |
|-------|-------|---------|
| `iat` | `1791020400` | Issued At |
| `exp` | `1791063600` | Expiration |

Converting those Unix timestamps (UTC):

+ iat → 1791020400 = 2026-10-03 07:00:00 UTC

+ exp → 1791063600 = 2026-10-03 19:00:00 UTC

So this token is valid for 12 hours (43,200 seconds).

### What This Token Grants
This appears to be a POS (Point of Sale) authorization token with elevated privileges:

| Field | Interpretation |
|-------|----------------|
| `store: LDS-014` | Store/register ID |
| `terminal: hh-22` | Specific terminal |
| `discount_bps: 3000` | **30% discount** authority (basis points: 3000/10000) |
| `flags` | Permissions granted |
| `provisioned_for: h.mbatha` | The user this was issued to |

The Flags (Permissions)
+ pos.price_override — can override item prices

+ pos.void_line — can void/remove line items

+ pos.reprint — can reprint receipts

### Security Observations
A few things worth flagging:

+ This is a sensitive token. It grants price override + void + 30% discount authority. If leaked, someone could manipulate sales at that terminal.

+ No signature shown. A real JWT has three parts: header.payload.signature. You've only provided the payload + timestamps. Without the signature, this can't be verified — but if the signature is missing/ignored by the server, that's a critical vulnerability.

+ The malformed prefix (hZ3Vl) could indicate tampering or truncation. Worth investigating how this token was generated.

+ Don't share this token in public channels — treat it like a password until it expires.

If you're doing security testing (which this looks like it might be), the next steps would be to check:

+ Is the signature actually validated?

+ Can you change discount_bps to 10000 (100%) and have it accepted?

+ Is the token bound to the terminal, or can it be replayed elsewhere?

Want me to help decode the header segment or analyze the full JWT structure?


