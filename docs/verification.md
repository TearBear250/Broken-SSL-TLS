# Verification Guide — Modern TLS 1.2 Fallback Profile

This document explains how to verify that your server is correctly configured
according to the [Modern TLS 1.2 Fallback Profile](tls12-modern-fallback.md).

---

## 1. Using `openssl s_client`

`openssl s_client` ships with every OpenSSL installation and is the quickest
way to spot-check a server.

### Check negotiated protocol and cipher

```bash
openssl s_client -connect example.com:443 -brief 2>/dev/null
```

Expected output excerpt:
```
Protocol version: TLSv1.3          # or TLSv1.2 if client is TLS 1.2 only
Ciphersuite: TLS_AES_128_GCM_SHA256
```

### Force a TLS 1.2 connection (verify it negotiates a good cipher)

```bash
openssl s_client -connect example.com:443 \
  -tls1_2 \
  -cipher 'ECDHE-RSA-AES128-GCM-SHA256' \
  -brief 2>/dev/null
```

Expected: connection succeeds with `ECDHE-RSA-AES128-GCM-SHA256`.

### Confirm TLS 1.0 and 1.1 are rejected

```bash
openssl s_client -connect example.com:443 -tls1 2>&1 | tail -5
openssl s_client -connect example.com:443 -tls1_1 2>&1 | tail -5
```

Expected: both return an error such as:
```
140...error:...no protocols available
```
or the connection is closed/reset immediately.

### Confirm RSA key exchange is rejected

```bash
openssl s_client -connect example.com:443 \
  -tls1_2 \
  -cipher 'AES128-SHA' \
  2>&1 | tail -5
```

Expected: handshake failure — the server should reject a non-ECDHE cipher.

### Confirm CBC suites are rejected

```bash
openssl s_client -connect example.com:443 \
  -tls1_2 \
  -cipher 'ECDHE-RSA-AES128-SHA' \
  2>&1 | tail -5
```

Expected: handshake failure.

### Inspect the server certificate

```bash
openssl s_client -connect example.com:443 \
  -showcerts 2>/dev/null \
  | openssl x509 -noout -text \
  | grep -E 'Public Key Algorithm|RSA Public-Key|Public-Key|Signature Algorithm'
```

Expected:
- Key size ≥ 2048 bits (RSA) or P-256 / P-384 (EC).
- Signature algorithm using SHA-256 or SHA-384, **not** SHA-1.

---

## 2. Using `testssl.sh`

[testssl.sh](https://testssl.sh/) is a comprehensive, self-contained TLS
scanner that checks ciphers, protocols, vulnerabilities, and configuration.

### Installation (one-liner)

```bash
git clone --depth 1 https://github.com/drwetter/testssl.sh.git
cd testssl.sh
```

### Run a full scan

```bash
./testssl.sh example.com:443
```

### Key sections to review

| Section | What to verify |
|---------|---------------|
| **Protocols** | SSLv2, SSLv3, TLS 1, TLS 1.1 all show `not offered`. TLS 1.2 and TLS 1.3 show `offered`. |
| **Cipher order** | Ciphers are ECDHE + AEAD only. |
| **Forward Secrecy** | Shows `ECDHE` (X25519 or P-256). No `RSA` key exchange. |
| **Cipher suites** | Only `AES_GCM` and `CHACHA20_POLY1305` variants. No `CBC`, no `3DES`, no `RC4`. |
| **Vulnerabilities** | POODLE, BEAST, LUCKY13, SWEET32, CRIME should all be `not vulnerable`. |
| **Certificate** | Key ≥ 2048 bits RSA or EC P-256/P-384. Signature SHA-256+. Not expired. |

### Targeted cipher-only scan

```bash
./testssl.sh --cipher-per-proto example.com:443
```

Scan output for TLS 1.2 should list **only** GCM or ChaCha20 suites.

### Check for specific vulnerabilities

```bash
./testssl.sh --poodle --beast --crime --sweet32 --robot example.com:443
```

All should report `not vulnerable`.

---

## 3. SSLLabs Online Checker (optional)

[SSL Labs Server Test](https://www.ssllabs.com/ssltest/) provides a detailed
web-based report.

### Expected results for this profile

| Check | Expected value |
|-------|---------------|
| Overall grade | **A** or **A+** (A+ requires HSTS with long max-age) |
| Protocol support | TLS 1.2 ✓, TLS 1.3 ✓; TLS 1.0 ✗, TLS 1.1 ✗ |
| Key exchange | 100 / 100 (ECDHE with X25519 or P-256) |
| Cipher strength | 90+ (all suites 128-bit+ AEAD) |
| Forward Secrecy | Yes (all simulated clients) |
| ROBOT | Not vulnerable |
| POODLE (TLS) | Not vulnerable |
| Downgrade attack prevention | Yes |
| Certificate chain | Valid, trusted, no SHA-1, key ≥ 2048 |

To achieve **A+**, add an HSTS header at the HTTP/application layer:

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

---

## 4. Quick `nmap` check (protocol versions)

```bash
nmap --script ssl-enum-ciphers -p 443 example.com
```

For TLS 1.2 you should see only entries like:
```
TLSv1.2:
  ciphers:
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256     - A
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 - A
    ...
  compressors:
    NULL
  cipher preference: server
```

No `TLSv1.0`, `TLSv1.1`, no `RSA` Kx, no `CBC`, no `DES`/`3DES`.

---

## 5. Automated CI Integration

For continuous verification, add a `testssl.sh` step to your CI pipeline:

```bash
./testssl.sh --severity HIGH --exitcode example.com:443
echo "Exit code: $?"
# Non-zero exit code indicates HIGH or higher severity findings.
```

This ensures regressions in TLS configuration are caught before reaching
production.
