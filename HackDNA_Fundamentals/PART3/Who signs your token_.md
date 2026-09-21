## Crytography

This is a JWT (JSON Web Token), and its **header** and **payload** are just base64url-encoded — so they can be decoded directly. The **signature** cannot be verified without the relevant public key, but here's what the token contains.

### Investigate 
```Bash
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHBzOi8vandrcy5icmlnaHR3YXktY2RuLmV4YW1wbGUva2V5cy9wcm9kLmpzb24iLCJraWQiOiJwcm9kLTIwMjYtMDgifQ.eyJpc3MiOiJodHRwczovL2F1dGguYnJpZ2h0d2F5LmV4YW1wbGUiLCJhdWQiOiJodHRwczovL2FwaS5jYWxkZXJhLmV4YW1wbGUiLCJzdWIiOiJwYXJ0bmVyOmJyaWdodHdheS1mcmVpZ2h0Iiwic2NvcGUiOiJzaGlwbWVudHM6cmVhZCBzaGlwbWVudHM6d3JpdGUiLCJpYXQiOjE3ODk5ODEyMDAsImV4cCI6MTc4OTk4NDgwMH0.hQ2mJ0rV8nT4wXpL6sC1yB9dF3gK7aZeR5uN0iO2tM8vP4xS1kD6jH9bW3cY7fA2 Header { "alg": "RS256", "typ": "JWT", "jku": "https://jwks.brightway-cdn.example/keys/prod.json", "kid": "prod-2026-08" } Payload { "iss": "https://auth.brightway.example", "aud": "https://api.caldera.example", "sub": "partner:brightway-freight", "scope": "shipments:read shipments:write", "iat": 1789981200, "exp": 1789984800 } Signature RS256 hQ2mJ0rV8nT4wXpL6sC1yB9dF3gK7aZeR5uN0iO2tM8vP4xS1kD6jH9bW3cY7fA2 Reset token Your answer Host the verifier would fetch the signing key from:

```

## Header

json

```
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://jwks.brightway-cdn.example/keys/prod.json",
  "kid": "prod-2026-08"
}
```

svgsvg

- **alg**: RS256 (RSA SHA-256)
- **typ**: JWT
- **jku**: JWKS URL where the signing keys are published
- **kid**: Key ID `prod-2026-08`

## Payload

json

```
{
  "iss": "https://auth.brightway.example",
  "aud": "https://api.caldera.example",
  "sub": "partner:brightway-freight",
  "scope": "shipments: read shipments: write",
  "iat": 1789981200,
  "exp": 1789984800
}
```



Decoded claims:

| **ClaimValueMeaning** |                                  |                                |
| --------------------- | -------------------------------- | ------------------------------ |
| `iss`                 | `https://auth.brightway.example` | Issuer                         |
| `aud`                 | `https://api.caldera.example`    | Intended audience (API)        |
| `sub`                 | `partner:brightway-freight`      | Subject — the partner identity |
| `scope`               | `shipments:read shipments:write` | Permissions granted            |
| `iat`                 | 1789981200                       | Issued at                      |
| `exp`                 | 1789984800                       | Expires at                     |

## Time notes

- `iat` = **2026-09-21 13:00:00 UTC**
- `exp` = **2026-09-21 14:00:00 UTC**
- Validity window: **1 hour**

## Signature

The third part (`hQ2mJ0rV8nT4wXpL6sC1yB9dF3gK7aZeR5uN0iO2tM8vP4xS1kD6jH9bW3cY7fA2`) is the RS256 signature. It **cannot be decoded** — it's a cryptographic signature over the header and payload. Verifying it requires the public key from the JWKS endpoint in the `jku` header (and you should always validate that the `jku`/`kid` are trusted before trusting the token).

## ⚠️ Important caveats

A few things stand out that you should treat as red flags if this is a real token:

1. **`jku`** **points to an external URL** (`brightway-cdn.example`). The `jku` header is a known attack vector — if an application blindly fetches keys from whatever `jku` says, an attacker can host their own JWKS and forge tokens. Never trust `jku` without allow-listing.
2. **`.example`** **domains are reserved for documentation/testing** — so this is very likely a sample/demo token, not a production credential.
3. **The** **`exp`** **is in 2026** — depending on when you're reading this, the token may not yet be valid (or may be a fabricated test case).

If you just wanted the contents: the token grants the `brightway-freight` partner read/write access to shipments on the `api.caldera.example` API, valid for one hour on 2026-09-21. If you need it *verified*, you'd need the public key from the `jku` endpoint.

*This response is AI-generated, for reference only.*

This was the mission  Mission briefing Hide briefing Caldera's shipment API accepts signed tokens from partner carriers. A token arrives; the API needs the public key that will verify it, and the library it uses is helpful: rather than making the team maintain a list of partner keys, it reads where to fetch the key from the token itself. That is a real header field; it is in the specification, and libraries really do honour it. Three different hostnames appear in this token, and they are all plausible. Only one of them decides whether the signature is trusted, and it is the one an attacker gets to choose. Decode the token and submit the host the verifier would go to for the key.  Investigate eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHBzOi8vandrcy5icmlnaHR3YXktY2RuLmV4YW1wbGUva2V5cy9wcm9kLmpzb24iLCJraWQiOiJwcm9kLTIwMjYtMDgifQ.eyJpc3MiOiJodHRwczovL2F1dGguYnJpZ2h0d2F5LmV4YW1wbGUiLCJhdWQiOiJodHRwczovL2FwaS5jYWxkZXJhLmV4YW1wbGUiLCJzdWIiOiJwYXJ0bmVyOmJyaWdodHdheS1mcmVpZ2h0Iiwic2NvcGUiOiJzaGlwbWVudHM6cmVhZCBzaGlwbWVudHM6d3JpdGUiLCJpYXQiOjE3ODk5ODEyMDAsImV4cCI6MTc4OTk4NDgwMH0.hQ2mJ0rV8nT4wXpL6sC1yB9dF3gK7aZeR5uN0iO2tM8vP4xS1kD6jH9bW3cY7fA2 Header {   "alg": "RS256",   "typ": "JWT",   "jku": "https\://jwks.brightway-cdn.example/keys/prod.json",   "kid": "prod-2026-08" } Payload {   "iss": "https\://auth.brightway.example",   "aud": "https\://api.caldera.example",   "sub": "partner\:brightway-freight",   "scope": "shipments\:read shipments\:write",   "iat": 1789981200,   "exp": 1789984800 } Signature RS256 hQ2mJ0rV8nT4wXpL6sC1yB9dF3gK7aZeR5uN0iO2tM8vP4xS1kD6jH9bW3cY7fA2 Reset token Your answer Host the verifier would fetch the signing key from:

svg

The host the verifier would fetch the signing key from is:

**`jwks.brightway-cdn.example`**

The `jku` (JWK Set URL) header tells the verifying library where to download the public keys. It's attacker-controlled, which is exactly the vulnerability — a forged token can point `jku` at a server the attacker runs and supply a matching key.

How it works Three hosts, three different jobs, and only one of them is a key source. The payload carries iss set to https\://auth.brightway.example, which says who claims to have issued the token, and aud set to https\://api.caldera.example, which says who the token is for. Neither is consulted to find a key: iss is a claim inside the signed body, and checking it before verification would be circular. The header carries kid, prod-2026-08, which names a key but does not say where it lives, and jku, https\://jwks.brightway-cdn.example/keys/prod.json. jku is the JWK Set URL. It is defined in RFC 7515, it means fetch the verification keys from here, and a library that honours it will make that HTTP request before it validates anything. So the host is jwks.brightway-cdn.example. Now see why that is fatal. The header is not signed in any way the verifier can use before it has a key, so whoever sends the token writes the header, including jku. An attacker generates their own key pair, signs a token with whatever claims they like, publishes the matching public key as a JWK Set on a host they control, points jku at it, and the verifier obligingly downloads the attacker's key and confirms that the attacker's signature is valid. The signature check passes honestly; it was just performed against the wrong key. Note that the lookalike host helps the attack survive a human review: brightway-cdn.example reads like partner infrastructure next to auth.brightway.example, but it is a separate registration and the two have nothing to do with each other. The answer is jwks.brightway-cdn.example.   lets write a report in markdown raw language

svg

markdown

```
# JWT `jku` Header Injection — Report

## Summary

A shipment API for Caldera accepts signed JWTs from partner carriers. Rather than
maintaining a static allow-list of partner public keys, the verification library
is configured (or defaults) to read the key location from the token itself — the
`jku` (JWK Set URL) header. Because the header is attacker-controlled and is
consulted *before* any signature validation, an attacker can supply their own
signing key and have their forged token accepted.

## Token Under Analysis

```

svgsvg

eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHBzOi8vandrcy5icmlnaHR3YXktY2RuLmV4YW1wbGUva2V5cy9wcm9kLmpzb24iLCJraWQiOiJwcm9kLTIwMjYtMDgifQ.eyJpc3MiOiJodHRwczovL2F1dGguYnJpZ2h0d2F5LmV4YW1wbGUiLCJhdWQiOiJodHRwczovL2FwaS5jYWxkZXJhLmV4YW1wbGUiLCJzdWIiOiJwYXJ0bmVyOmJyaWdodHdheS1mcmVpZ2h0Iiwic2NvcGUiOiJzaGlwbWVudHM6cmVhZCBzaGlwbWVudHM6d3JpdGUiLCJpYXQiOjE3ODk5ODEyMDAsImV4cCI6MTc4OTk4NDgwMH0.hQ2mJ0rV8nT4wXpL6sC1yB9dF3gK7aZeR5uN0iO2tM8vP4xS1kD6jH9bW3cY7fA2

text

````
### Header

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://jwks.brightway-cdn.example/keys/prod.json",
  "kid": "prod-2026-08"
}
````

svgsvg

### Payload

json

```
{
  "iss": "https://auth.brightway.example",
  "aud": "https://api.caldera.example",
  "sub": "partner:brightway-freight",
  "scope": "shipments:read shipments:write",
  "iat": 1789981200,
  "exp": 1789984800
}
```

svgsvg

## Three Hosts, Three Different Jobs

| **HostFieldRole**            |       |                                                                                                                                                     |
| ---------------------------- | ----- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `auth.brightway.example`     | `iss` | *Claims* who issued the token. Not consulted for key discovery. A claim inside the signed body — checking it before verification would be circular. |
| `api.caldera.example`        | `aud` | *Claims* who the token is for. Not a key source.                                                                                                    |
| `jwks.brightway-cdn.example` | `jku` | **JWK Set URL — the key source.** This is the one the verifier fetches from.                                                                        |

- **`iss`** — issuer claim, inside the signed payload.
- **`aud`** — audience claim, inside the signed payload.
- **`kid`** — names a key (`prod-2026-08`) but does not say where it lives.
- **`jku`** — defined in RFC 7515. Means *"fetch the verification keys from here."*
  A library that honors it makes the HTTP request **before** validating anything.

## The Vulnerability

The header is **not signed** in any way the verifier can use before it has a key.
Whoever sends the token writes the header — including `jku`.

### Attack Steps

1. Attacker generates their own RSA key pair.
2. Attacker crafts a token with arbitrary claims (e.g., elevated scope,
   impersonated partner), signs it with their private key.
3. Attacker publishes the matching public key as a JWK Set on a host they control.
4. Attacker sets `jku` in the header to point at that host.
5. The verifier downloads the attacker's key and confirms the attacker's signature
   is valid.

The signature check **passes honestly** — it was simply performed against the
**wrong key**.

## Why the Lookalike Host Helps the Attack

`brightway-cdn.example` reads like partner infrastructure sitting next to
`auth.brightway.example`. In a human review it looks plausible — but it is a
**separate registration** with nothing to do with the real issuer. This social
camouflage lets the attack survive casual inspection.

## Answer

> **Host the verifier would fetch the signing key from:**
> `jwks.brightway-cdn.example`

## Remediation

- **Never trust** **`jku`** **(or** **`jwk`****/****`x5u`****) from an untrusted token.** Ignore these
  headers entirely, or allow-list the exact URLs permitted.
- **Pin keys out-of-band.** Configure the verifier with a static JWKS per partner
  (or a fixed, allow-listed JWKS endpoint). Resolve `kid` only against that
  trusted set.
- **Validate in the right order:** fetch keys from a trusted source, verify the
  signature, *then* evaluate `iss` / `aud` / `exp` claims.
- **Validate** **`iss`** **and** **`aud`** against expected values — but only after the
  signature is verified.
- **Short expiries alone do not help** — the forgery is valid for its whole window.
- **Reject** **`alg`** **confusion** (`none`, HS256-signed-with-public-key) as a related
  class of JWT header abuse.

## References

- RFC 7515 — JSON Web Signature (JWS), `jku` header
- RFC 7517 — JSON Web Key (JWK)
- RFC 7519 — JSON Web Token (JWT)
- OWASP — JWT / JWK header injection guidance

text

```
Key takeaway: the three hosts look interchangeable but only `jku` drives key
lookup, and `jku` is attacker-chosen — so the verifier happily trusts a key the
attacker supplied.
```

svgsvg

*This response is AI-generated, for reference only.*
