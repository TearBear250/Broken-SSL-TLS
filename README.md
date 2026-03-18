# Broken-SSL-TLS

Educational repository about SSL/TLS — what goes wrong with legacy configurations,
and how to configure modern, hardened TLS correctly.

> **Scope:** The configurations and documentation here are for *education and
> reference only*. They demonstrate best-practice settings; they are not a
> substitute for a full security review of your specific deployment.

---

## Modern TLS 1.2 Fallback Docs and Reference Configs

The following files provide a **hardened TLS 1.2 fallback profile** (with
TLS 1.3 preferred) for common web servers and proxies.

### Documentation

- [docs/tls12-modern-fallback.md](docs/tls12-modern-fallback.md) — Profile
  definition: allowed protocols, key exchange, cipher suites, certificates,
  session tickets, renegotiation, and how the profile compares to TLS 1.3.
- [docs/verification.md](docs/verification.md) — How to verify your server
  with `openssl s_client`, `testssl.sh`, SSL Labs, and `nmap`.

### Reference Configurations

| Platform | File |
|----------|------|
| Nginx | [configs/nginx-tls12-fallback.conf](configs/nginx-tls12-fallback.conf) |
| Apache HTTPD | [configs/apache-tls12-fallback.conf](configs/apache-tls12-fallback.conf) |
| HAProxy | [configs/haproxy-tls12-fallback.cfg](configs/haproxy-tls12-fallback.cfg) |
| HAProxy — TLS 1.2 cipher list | [configs/haproxy-tls12-ciphers.txt](configs/haproxy-tls12-ciphers.txt) |
| HAProxy — TLS 1.3 cipher suites | [configs/haproxy-tls13-ciphersuites.txt](configs/haproxy-tls13-ciphersuites.txt) |
| Envoy | [configs/envoy-downstream-tls.yaml](configs/envoy-downstream-tls.yaml) |

### Key Principles

- **TLS 1.3 first.** TLS 1.2 is only used when a client cannot negotiate 1.3.
- **ECDHE-only key exchange** (forward secrecy). RSA key exchange is disabled.
- **AEAD ciphers only** (AES-GCM, ChaCha20-Poly1305). No CBC, no 3DES, no RC4.
- **No TLS 1.0 or 1.1**, no SSL 3, no compression, no EXPORT suites.
- **Modern certificates**: RSA 2048+ or ECDSA P-256; SHA-256+ signatures.

---

## What "Broken SSL/TLS" Means (Historical Context)

This repository originally documented misconfigured / deliberately weakened
TLS as an educational anti-pattern. Examples of *broken* TLS include:

- Enabling SSLv3 (POODLE, CVE-2014-3566)
- Using RSA key exchange without forward secrecy
- Allowing CBC-mode ciphers (BEAST, LUCKY13, padding oracles)
- Using RC4 (NOMORE attack)
- Using 3DES (SWEET32, CVE-2016-2183)
- Enabling TLS compression (CRIME, CVE-2012-4929)
- Using SHA-1 certificates
- Allowing TLS 1.0 / 1.1 (deprecated by RFC 8996)

The configs and docs above show how to avoid all of these.

---

## License

See [LICENSE](LICENSE).
