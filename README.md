# Broken SSL/TLS

> **⚠️ WARNING – Educational Use Only**
> This library is **intentionally insecure**. It models well-known SSL/TLS
> vulnerabilities so developers and students can study them hands-on.
> **Never use this code for real network communication or production security.**

---

## What Is This?

Broken SSL/TLS is a pure-Python library that simulates the cryptographic
weaknesses found in old, misconfigured, or export-grade SSL/TLS
implementations. It is designed to help learners:

* Understand *why* SSL 2.0, SSL 3.0, and TLS 1.0 were deprecated
* Inspect the byte-level structure of a TLS handshake
* See how broken cipher suites (NULL, RC4, DES, export-grade) behave
* Explore certificate-validation flaws that enable man-in-the-middle attacks
* Observe record-layer vulnerabilities such as padding oracles and weak MACs

The library contains **no real networking code** – all protocol messages are
built in memory so you can safely run it in any environment.

---

## Vulnerabilities Demonstrated

| Module | Vulnerability | CVE / Attack Name |
|--------|--------------|-------------------|
| `protocol.py` | SSL 2.0 / SSL 3.0 negotiation | DROWN (CVE-2016-0800), POODLE (CVE-2014-3566) |
| `protocol.py` | TLS compression | CRIME (CVE-2012-4929) |
| `protocol.py` | Weak PRNG (time-seeded LCG) | CVE-2008-0166 (Debian OpenSSL) |
| `protocol.py` | SSL 3.0 non-HMAC PRF | Length-extension key recovery |
| `ciphers.py` | NULL cipher – no encryption | CWE-311 |
| `ciphers.py` | RC4 stream cipher | Bar Mitzvah (CVE-2015-2808) |
| `ciphers.py` | 40-bit export cipher | FREAK (CVE-2015-0204) |
| `ciphers.py` | 56-bit DES + zero IV (CBC) | BEAST (CVE-2011-3389) |
| `certificates.py` | No certificate chain verification | CWE-295 |
| `certificates.py` | No hostname verification | CWE-297 |
| `certificates.py` | Expired / self-signed certs accepted | – |
| `certificates.py` | MD5 / SHA-1 signatures accepted | SHAttered, CVE-2004-2761 |
| `certificates.py` | Short (512-bit) RSA keys accepted | FREAK (CVE-2015-0204) |
| `record.py` | MAC-then-Encrypt + padding oracle | POODLE (CVE-2014-3566), Lucky13 (CVE-2013-0169) |
| `record.py` | Truncated HMAC | RFC 4366 §3.7 weakness |
| `record.py` | NULL MAC – no integrity | CWE-354 |

---

## Repository Layout

```
broken_ssl_tls/
  __init__.py        – Package exports
  protocol.py        – ProtocolVersion enum, BrokenTLSContext, BrokenTLSHandshake
  ciphers.py         – NullCipher, RC4Cipher, WeakExportCipher, DESCipher
  certificates.py    – CertificateInfo, ValidationResult, BrokenCertValidator
  record.py          – BrokenTLSRecord, BrokenMAC

tests/
  test_broken_ssl_tls.py   – 65 unit tests (Python unittest)
```

---

## Quick Start

No dependencies beyond the Python standard library (Python 3.8+).

```python
from broken_ssl_tls import BrokenTLSContext, ProtocolVersion

# Create a context with every bad default enabled
ctx = BrokenTLSContext()

# Print all active vulnerabilities
for v in ctx.get_vulnerability_report():
    print(f"[{v['severity']}] {v['title']}: {v['description']}")
```

### Simulate a broken handshake

```python
ctx = BrokenTLSContext()
hs = ctx.create_handshake("example.com")

client_hello = hs.create_client_hello()
server_hello = hs.simulate_server_hello()

print("Negotiated version:", hs.negotiated_version)
print("Negotiated cipher :", hs.negotiated_cipher)

# Derive master secret using the broken SSL 3.0 PRF
ms = hs.compute_master_secret(b"\x03\x00" + b"\xAB" * 46)
print("Master secret (hex):", ms.hex())
```

### Inspect broken certificate validation

```python
import time
from broken_ssl_tls import BrokenCertValidator
from broken_ssl_tls.certificates import CertificateInfo

cert = CertificateInfo(
    subject="CN=evil.example.com",
    issuer="CN=Rogue CA",
    not_before=0.0,
    not_after=1.0,           # expired in 1970!
    public_key_bits=512,
    signature_algorithm="md5WithRSAEncryption",
    self_signed=True,
)

validator = BrokenCertValidator()   # all checks disabled by default
result = validator.validate(cert, hostname="bank.example.com")
print("Valid?   ", result.valid)    # True – everything is accepted!
print("Warnings:", result.warnings)

# Now enable all checks
validator.verify_chain       = True
validator.reject_self_signed = True
validator.verify_expiry      = True
validator.verify_hostname    = True
validator.reject_weak_signature = True
validator.minimum_key_bits   = 2048

result = validator.validate(cert, hostname="bank.example.com")
print("Valid?  ", result.valid)    # False – cert rejected
print("Errors: ", result.errors)
```

### Use the broken ciphers directly

```python
from broken_ssl_tls import NullCipher, RC4Cipher, WeakExportCipher

# NULL cipher: zero security
nc = NullCipher()
print(nc.encrypt(b"secret"))       # b'secret' – plaintext!

# RC4: key reuse leaks XOR of plaintexts
rc4 = RC4Cipher()
key = b"reused_session_k"
c1 = rc4.encrypt(b"Transfer $1000", key)
c2 = rc4.encrypt(b"Transfer $9999", key)
xor = bytes(a ^ b for a, b in zip(c1, c2))
print(xor)  # == XOR of plaintexts; attacker can use this to recover data

# Export cipher: 40-bit key, brute-forceable in minutes
exp = WeakExportCipher()
key40 = b"\x01\x02\x03\x04\x05"   # 40 bits = 2^40 keyspace
ct = exp.encrypt(b"Confidential", key40)
print(exp.decrypt(ct, key40))      # b'Confidential'
```

### Padding oracle explanation

```python
from broken_ssl_tls import BrokenTLSRecord

record = BrokenTLSRecord(version=(3, 0))   # SSL 3.0
print(record.demonstrate_padding_oracle())
```

---

## Running the Tests

```bash
python -m unittest discover -s tests -v
```

All 65 tests should pass with no external dependencies.

---

## How SSL/TLS Works (Background)

SSL (Secure Sockets Layer) and TLS (Transport Layer Security) are
cryptographic protocols that protect data sent over a network. A simplified
flow:

1. **Handshake** – Client and server negotiate a protocol version, cipher
   suite, and exchange key material.
2. **Authentication** – The server presents an X.509 certificate; the client
   verifies it against a trusted Certificate Authority.
3. **Key derivation** – Both sides derive symmetric session keys from the
   exchanged material.
4. **Record layer** – Application data is encrypted and integrity-protected
   using the negotiated cipher and MAC.

Each step above has historically had vulnerabilities. This library lets you
observe exactly what goes wrong when each protection is disabled or weakened.

---

## License

Eclipse Public License v2.0 – see [LICENSE](LICENSE).
