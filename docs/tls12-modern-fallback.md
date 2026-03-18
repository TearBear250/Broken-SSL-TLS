# Modern Hardened TLS 1.2 Fallback Profile

## Purpose

TLS 1.3 is the preferred and recommended protocol for all new deployments.
It has a simpler handshake, a tighter set of mandatory cipher suites, and
stronger privacy properties.

However, some clients — older embedded devices, legacy JVMs, some enterprise
middleware, older Android versions — do not yet support TLS 1.3. Rather than
dropping back to a loosely-configured TLS 1.2 that re-enables historical
foot-guns (RSA key exchange, CBC mode ciphers, 3DES, RC4, compression), this
profile locks TLS 1.2 down to look as close as practical to TLS 1.3.

**Policy: TLS 1.3 first. TLS 1.2 only as a locked-down fallback.**

---

## Modern TLS 1.2 Fallback Profile

### Protocol Versions

| Action  | Versions |
|---------|----------|
| Enable  | TLS 1.3, TLS 1.2 |
| Disable | SSLv2, SSLv3, TLS 1.0, TLS 1.1 |

TLS 1.0 and 1.1 are deprecated by RFC 8996 and must be disabled.

---

### Key Exchange — ECDHE Only

All TLS 1.2 connections must use **ECDHE** (Elliptic-Curve Diffie-Hellman
Ephemeral). This provides **forward secrecy**: even if the server's private key
is later compromised, past session traffic cannot be decrypted.

RSA key exchange (`TLS_RSA_*`) must be **disabled**. It provides no forward
secrecy and is one of the primary weaknesses in legacy TLS 1.2 deployments.

**Preferred curves / groups (in order of preference):**

1. **X25519** — fast, modern, constant-time; preferred wherever available.
2. **secp256r1 (P-256)** — NIST curve; widely supported fallback.

---

### Cipher Suites — AEAD Only

Only AEAD (Authenticated Encryption with Associated Data) suites are permitted.
These provide both confidentiality and integrity in one operation and are not
vulnerable to padding-oracle attacks that affect CBC-mode suites.

**TLS 1.2 allowed suites (OpenSSL names):**

```
ECDHE-ECDSA-AES128-GCM-SHA256
ECDHE-RSA-AES128-GCM-SHA256
ECDHE-ECDSA-CHACHA20-POLY1305
ECDHE-RSA-CHACHA20-POLY1305
ECDHE-ECDSA-AES256-GCM-SHA384   (optional; larger key, minimal extra benefit)
ECDHE-RSA-AES256-GCM-SHA384     (optional)
```

**TLS 1.3 suites (negotiated separately from TLS 1.2 in OpenSSL):**

```
TLS_AES_128_GCM_SHA256
TLS_CHACHA20_POLY1305_SHA256
TLS_AES_256_GCM_SHA384
```

**Explicitly disabled:**

- `TLS_RSA_*` (no forward secrecy)
- All `*_CBC_*` suites (padding oracle risk)
- 3DES (`*DES*`)
- RC4 (`*RC4*`)
- EXPORT suites (`*EXPORT*`)
- NULL suites (`*NULL*`)
- Anonymous suites (`*aNULL*`, `*eNULL*`)

---

### Authentication — Certificates and Signatures

| Requirement | Guidance |
|-------------|----------|
| RSA key size | 2048-bit minimum; 3072 or 4096 recommended for new issuance |
| EC key | ECDSA P-256 or P-384 |
| Signature hash | SHA-256 or SHA-384; avoid SHA-1 entirely |
| Signature scheme | Prefer RSA-PSS or ECDSA; avoid PKCS#1v1.5 where the stack supports RSA-PSS |

Some stacks support **dual certificates** (one RSA, one ECDSA). Where supported
this allows serving ECDSA to modern clients and RSA to older ones.

---

### Session Tickets

TLS session tickets allow resumption without a full handshake. They also carry
a risk: if the ticket encryption key is static or leaked, past sessions may be
resumable.

Guidance:

- **Preferred:** disable session tickets (`ssl_session_tickets off`) unless you
  have a key-rotation mechanism in place.
- If you require tickets for performance: rotate ticket keys frequently (every
  few hours) and do not persist them across restarts.
- Session IDs (server-side cache) are less risky than tickets because the server
  controls the cache lifetime.

---

### Renegotiation

- **Disable insecure renegotiation.** Modern OpenSSL does this by default
  (`SSL_OP_NO_SSLv2` etc.), but explicitly setting `ssl_verify_client off` and
  not enabling `SSLVerifyClient require` avoids triggering renegotiation.
- **Disable client-initiated renegotiation** where your stack supports it, to
  prevent CPU exhaustion (THC-SSL-DOS style attacks).

---

### Compression

**Disable TLS-layer compression entirely.** TLS compression is vulnerable to
the CRIME attack (CVE-2012-4929). Modern servers default to off; verify yours
has `SSLCompression off` (Apache) or no `zlib` in Nginx.

---

## What Differs From TLS 1.3

Even this hardened TLS 1.2 profile differs from TLS 1.3 in important ways:

| Property | TLS 1.3 | Hardened TLS 1.2 |
|----------|---------|------------------|
| Handshake round trips | 1-RTT (0-RTT with session resumption) | 2-RTT |
| Forward secrecy | Mandatory (ECDHE only) | Enforced by this profile; not mandatory in the spec |
| Cipher selection | Spec-mandatory; no negotiation footgun | Manually configured; misconfiguration possible |
| Handshake encryption | Certificate encrypted in handshake | Certificate visible in handshake |
| Downgrade protection | Built-in (random value sentinel) | Depends on implementation |
| Legacy surface area | Minimal | Larger; more ways to misconfigure |
| RSA key exchange | Removed from spec | Must be manually disabled |
| CBC mode | Removed from spec | Must be manually disabled |
| Compression | Removed from spec | Must be manually disabled |

**Bottom line:** TLS 1.3 is safer by default. TLS 1.2 (even hardened) requires
deliberate, correct configuration to reach a comparable security level.

---

## Compatibility Caveats

| Scenario | Notes |
|----------|-------|
| OpenSSL < 1.1.1 | No TLS 1.3 support; X25519 may not be available. Upgrade strongly recommended. |
| OpenSSL < 1.0.2 | No ECDHE for TLS 1.2; P-256 requires OpenSSL 1.0.2+. Upgrade. |
| Old Android (< 5.0) | May not support CHACHA20-POLY1305; AES-GCM will be used instead. |
| Java 8u261 and earlier | May not support X25519; P-256 will be used as fallback. |
| Old Windows / IE 11 | TLS 1.2 supported; ECDHE-AES-GCM generally works. |
| HAProxy < 2.2 | `ssl-min-ver`/`ssl-max-ver` syntax requires 2.2+. |
| Envoy | Cipher suite names follow OpenSSL conventions in BoringSSL; confirm against your Envoy version. |

If a client does not support any of the listed ECDHE+AEAD suites, the
connection will fail. That is intentional — the alternative is enabling
insecure suites. For genuinely legacy clients that cannot be upgraded, the
appropriate action is to use a dedicated endpoint with an isolated, more
permissive policy that does not affect the general population.

---

## Quick Reference — Cipher String for OpenSSL

```
ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
```

You can verify the list expands correctly with:

```bash
openssl ciphers -v 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'
```

Verify no unwanted suites are included:

```bash
openssl ciphers -v '...' | grep -E 'CBC|RSA Kx|RC4|DES|EXPORT|NULL'
# Expected: no output
```
