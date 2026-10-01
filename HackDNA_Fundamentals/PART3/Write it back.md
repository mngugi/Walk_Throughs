## How It Works

Reverse `Kestrel-88` and you get `88-lertseK`. Base64 that and you get
`ODgtbGVydHNlSw==`, which is what the login routine will compare against
when somebody types `Kestrel-88`.

Order is the whole exercise: Base64 first and then reverse produces a
different string. It does not reproduce the value expected by the login
routine, so the authentication attempt fails.

What makes this worth doing is the direction. Every one of these challenges
so far has pulled a secret out of an encoding. Here the encoding is run
forward, and that is the difference between a hash and a transformation.

A hash is a one-way function: knowing the stored value and the algorithm does
not provide a direct way to recover the original password. A reversible
transformation gives up that protection.

Anyone who can read `pw_enc` can reverse the transformation to recover the
passwords stored in the system. Anyone who can write to `pw_enc` can
construct a value corresponding to a chosen password.

### Transformation

```text
Password
   ↓
Reverse
   ↓
Base64 Encode
   ↓
pw_enc

---

For example

```text
Kestrel-88
    ↓
88-lertseK
    ↓
ODgtbGVydHNlSw==

```
Security Lesson

The fundamental weakness is that pw_enc is not a password hash.
It is a reversible encoding.

A secure password-storage system should use a purpose-built password
hashing/KDF mechanism such as Argon2id, scrypt, or bcrypt, together with
appropriate parameters and unique salts.
