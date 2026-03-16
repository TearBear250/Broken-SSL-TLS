# Broken-SSL-TLS

> **EDUCATIONAL PURPOSES ONLY – DO NOT USE IN PRODUCTION**

A rough-draft, intentionally broken implementation of SSL and TLS, written
in pure Python (standard library only).  The goal is to lay out *what* SSL
and TLS are conceptually, while deliberately reproducing the well-known
weaknesses found in historical deployments – so that learners can see
exactly how each vulnerability works and understand how to do better.

---

## What is this?

Modern consumers interact with HTTPS dozens of times a day, but most have
no idea what SSL/TLS actually does.  This project provides:

- **`broken_ssl.py`** – an SSL 3.0-inspired implementation with documented
  weaknesses.
- **`broken_tls.py`** – a TLS 1.0-inspired implementation with documented
  weaknesses.
- **`tests/`** – unit tests that exercise each module *and* assert that the
  intentional weaknesses are observable (so future contributors know exactly
  what needs fixing).

---

## Repository layout

```
broken_ssl.py      Experimental (broken) SSL implementation
broken_tls.py      Experimental (broken) TLS implementation
tests/
  test_ssl.py      Unit tests for broken_ssl.py
  test_tls.py      Unit tests for broken_tls.py
```

---

## Running the tests

```bash
python -m pytest tests/          # requires pytest
# or without pytest:
python -m unittest discover tests/
```

---

## Intentional weaknesses

### SSL (`broken_ssl.py`)

| # | Weakness | Real CVE / Attack |
|---|----------|-------------------|
| 1 | SSL 3.0 version negotiated | POODLE – CVE-2014-3566 |
| 2 | RC4 stream cipher | RC4 NOMORE – CVE-2015-2808 |
| 3 | MD5 used for MAC (not HMAC) | Collision / length-extension |
| 4 | NULL cipher suite advertised | No encryption at all |
| 5 | 40-bit export-grade RC4 | FREAK – CVE-2015-0204 |
| 6 | Deflate compression offered | CRIME – CVE-2012-4929 |
| 7 | MAC-then-Encrypt | Lucky13 / POODLE padding oracle |
| 8 | No certificate verification | MITM |
| 9 | No sequence number in MAC | Replay attacks |
| 10 | Hardcoded fallback session key | Static key compromise |
| 11 | Timestamp in client_random | Information leak |
| 12 | SSL 3.0 PRF (MD5 + SHA-1) | SLOTH – CVE-2015-7575 |
| 13 | Non-constant-time MAC compare | Timing oracle |

### TLS (`broken_tls.py`)

| # | Weakness | Real CVE / Attack |
|---|----------|-------------------|
| 1 | TLS 1.0 with CBC | BEAST – CVE-2011-3389 |
| 2 | Chained/predictable CBC IV | BEAST – CVE-2011-3389 |
| 3 | AES-CBC simulated with XOR | Trivially breakable |
| 4 | MAC-then-Encrypt | Lucky13 – CVE-2013-0169 |
| 5 | Silent / weak padding check | POODLE – CVE-2014-3566 |
| 6 | Non-constant-time MAC compare | Timing oracle |
| 7 | RC4 cipher suites | RC4 NOMORE – CVE-2015-2808 |
| 8 | 3DES cipher suite | SWEET32 – CVE-2016-2183 |
| 9 | 40-bit export RC4 | FREAK – CVE-2015-0204 |
| 10 | NULL cipher suite | No encryption at all |
| 11 | Deflate compression | CRIME – CVE-2012-4929 |
| 12 | No certificate chain check | MITM |
| 13 | No OCSP / CRL check | Certificate revocation ignored |
| 14 | RSA key exchange, no FS | ROBOT – CVE-2017-13099 |
| 15 | Pre-master secret in the clear | Conceptual demonstration |
| 16 | TLS 1.0 PRF (MD5 + SHA-1) | SLOTH – CVE-2015-7575 |
| 17 | Timestamp in client_random | Information leak |
| 18 | No TLS_FALLBACK_SCSV | Downgrade – CVE-2014-3568 |
| 19 | Unsafe renegotiation | CVE-2009-3555 |
| 20 | Hardcoded fallback keys | Static key compromise |

---

## Quick example

```python
from broken_ssl import BrokenSSLConnection

conn = BrokenSSLConnection()
result = conn.do_handshake()
print("Master secret:", result['master_secret'].hex())

raw = conn.send(b"Hello, broken SSL!")
print("Encrypted record:", raw.hex())

# Recover the plaintext (same connection = same keys)
plaintext = conn.receive(raw)
print("Decrypted:", plaintext)
```

```python
from broken_tls import BrokenTLSConnection

conn = BrokenTLSConnection()
result = conn.do_handshake()
print("Master secret:", result['master_secret'].hex())

raw = conn.send(b"Hello, broken TLS!")
print("Encrypted record:", raw.hex())
```

---

## Disclaimer

This code is a **teaching tool**.  It intentionally omits or breaks security
controls.  Every weakness is documented inline with comments that reference
the relevant CVE or attack name.  The project exists so that someone can come
along, read the comments, and understand *exactly* what needs to be fixed to
build something secure.
