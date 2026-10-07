# TOTP Seed Exposure — Incident Notes

## 1. Summary

An encoded input file contains three `otpauth://` URIs in plaintext, obfuscated only by representing each ASCII character as its decimal code point. Decoded, the file exposes live TOTP shared seeds for three accounts. Anyone holding these seeds can generate valid 6-digit codes indefinitely, on any device, without the original phone and without triggering any alert.

## 2. The Encoded Input

The file begins with the literal string `Encoded input` followed by a long space-separated list of decimal integers. The decoder UI offers decimal / url / base64 / hex / rot13 / base32 transformations. Only one transformation is meaningful.

## 3. Decoding

### 3.1 Method

Each integer is an ASCII code point. Mapping `n → chr(n)` recovers the original text. This is not encryption and not a real encoding — it is text with spaces inserted between characters.

Example:

    111 116 112 97 117 116 104 58 47 47
     o   t   p  a   u   t   h   :  /  /

### 3.2 Decoded Output

Three lines, each an `otpauth://totp/...` URI:

    otpauth://totp/Fernpath%20Payroll:d.okonkwo@fernpath.example?secret=KRSXG5CTMVRXEZLU&issuer=Fernpath%20Payroll&digits=6&period=30
    otpauth://totp/Corvid%20Mail:d.okonkwo@fernpath.example?secret=MZXW6YTBOJSGC43F&issuer=Corvid%20Mail&digits=6&period=30
    otpauth://totp/Thornbury%20VPN:dokonkwo@thornbury.example?secret=NBSWY3DPFQQHO33S&issuer=Thornbury%20VPN&digits=6&period=30

## 4. What These URIs Are

The `otpauth://totp/` scheme is the standard Key URI Format used by authenticator apps. Each URI encodes everything an app needs to enroll an account:

| Field    | Meaning                                    |
|----------|--------------------------------------------|
| `label`  | Issuer + account, for display              |
| `issuer` | Service name                               |
| `secret` | Base32-encoded shared seed (the credential)|
| `digits` | Code length (6)                            |
| `period` | Time step in seconds (30)                  |

### 4.1 Extracted Seeds

| Service          | Account                        | Secret (Base32)      |
|------------------|--------------------------------|----------------------|
| Fernpath Payroll | d.okonkwo@fernpath.example     | `KRSXG5CTMVRXEZLU`   |
| Corvid Mail      | d.okonkwo@fernpath.example     | `MZXW6YTBOJSGC43F`   |
| Thornbury VPN    | dokonkwo@thornbury.example     | `NBSWY3DPFQQHO33S`   |

All three use 6 digits and a 30-second period.

## 5. Why This Matters

### 5.1 Seed vs. Code

A 6-digit TOTP code is a **derived, time-bound** value. The seed is the **generator**. The code cannot be reversed into the seed (HMAC-SHA1 is one-way), but the seed trivially produces every code the server will ever accept. The code is a symptom; the seed is the disease.

### 5.2 No Per-Device State

TOTP is stateless from the client's perspective. The server stores the same seed and computes the same codes. There is nothing device-specific to revoke by wiping the phone. A leaked seed remains valid until the server issues a new one.

### 5.3 Bearer Credential

The seed is a bearer credential. Whoever holds it can authenticate as the account holder for the second factor. Possession is sufficient; identity is irrelevant.

## 6. Root Causes

| # | Failure                                                              | Impact                                          |
|---|----------------------------------------------------------------------|-------------------------------------------------|
| 1 | Seed written to a preferences file included in platform backup by default | Seed leaves the device via cloud/desktop backup |
| 2 | Secret material stored alongside ordinary settings                   | No separation, no access controls, easy to exfiltrate |
| 3 | Reversible encoding mistaken for protection                          | False confidence; no real obscurity             |
| 4 | No rotation plan for exposed seeds                                   | Compromise persists after discovery             |

## 7. The Encoding Is Decoration

"Base10 per character" is not obfuscation. It is plaintext with different delimiters. Any reversible transformation (decimal, base64, hex, rot13, base32) provides zero protection against an adversary who has the file. Treating it as a security control is the third failure above.

## 8. Correct Storage

Seeds must live in hardware-backed, non-exportable, non-backed-up storage:

| Platform        | Correct mechanism                          | Key property                                  |
|-----------------|--------------------------------------------|-----------------------------------------------|
| Android         | Android Keystore / EncryptedSharedPreferences | Hardware-backed, non-exportable            |
| Android (backup)| `android:allowBackup="false"` or backup rules XML | Excludes file from Auto Backup          |
| iOS             | Keychain                                   | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`|
| iOS (backup)    | `NSURLIsExcludedFromBackupKey`             | Excludes file from iCloud/iTunes backup       |

The `ThisDeviceOnly` accessibility class on iOS and hardware-backed keys on Android are what keep the seed off other devices and out of backups. Preferences files (`SharedPreferences`, `UserDefaults`, plain `Documents/`) are the wrong place for secrets.

## 9. Remediation

1. **Rotate all three seeds.** Re-enroll 2FA for Fernpath Payroll, Corvid Mail, and Thornbury VPN. The server must issue new seeds; the old ones must be invalidated.
2. **Revoke active sessions** on the affected accounts.
3. **Audit the backup file** for other secrets that may have leaked the same way.
4. **Fix storage**: move seeds to Keystore/Keychain with device-only accessibility and backup exclusion.
5. **Remove the misleading decoder UI** or relabel it — it implies protection that does not exist.
6. **Add a rotation procedure** to the enrollment flow so future exposures have a defined response.

## 10. One-Line Takeaway

> A TOTP seed is a bearer credential. Encoding it does not protect it, backing it up leaks it, and the only real remedy is hardware-backed, non-exportable, non-backed-up storage — plus rotation the moment it leaves.
