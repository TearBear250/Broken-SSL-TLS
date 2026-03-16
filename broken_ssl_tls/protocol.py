"""
Broken TLS Protocol – Handshake Simulation
===========================================

This module simulates a TLS handshake with intentional security weaknesses.
It does *not* open any real network connections; it models the protocol
messages so students can inspect every field and understand where attacks
like POODLE, BEAST, FREAK, and DROWN originate.

WARNING: Intentionally insecure – for educational purposes only.
"""

import enum
import hashlib
import os
import struct
import time
from typing import List, Optional


# ---------------------------------------------------------------------------
# Protocol versions
# ---------------------------------------------------------------------------


class ProtocolVersion(enum.Enum):
    """
    SSL/TLS protocol version identifiers (major, minor byte pairs).

    Versions marked BROKEN or DEPRECATED must not be used in production.
    """

    SSL_2_0 = (0x00, 0x02)  # BROKEN – DROWN attack (CVE-2016-0800)
    SSL_3_0 = (0x03, 0x00)  # BROKEN – POODLE attack (CVE-2014-3566)
    TLS_1_0 = (0x03, 0x01)  # VULNERABLE – BEAST attack (CVE-2011-3389)
    TLS_1_1 = (0x03, 0x02)  # DEPRECATED – RFC 8996
    TLS_1_2 = (0x03, 0x03)  # Secure when properly configured
    TLS_1_3 = (0x03, 0x04)  # Current recommended version

    def to_bytes(self) -> bytes:
        return bytes(self.value)

    def __str__(self) -> str:
        return self.name.replace("_", " ")


# ---------------------------------------------------------------------------
# Cipher suite identifiers
# ---------------------------------------------------------------------------


class CipherSuiteID(enum.Enum):
    """
    IANA cipher suite codes (RFC 5246 Appendix A.5) including insecure ones.
    """

    TLS_NULL_WITH_NULL_NULL = 0x0000           # RFC 5246 – No security at all
    TLS_RSA_WITH_NULL_MD5 = 0x0001             # RFC 5246 – No encryption
    TLS_RSA_WITH_NULL_SHA = 0x0002             # RFC 5246 – No encryption
    TLS_RSA_EXPORT_WITH_RC4_40_MD5 = 0x0003   # RFC 4346 – FREAK (CVE-2015-0204)
    TLS_RSA_WITH_RC4_128_MD5 = 0x0004          # RFC 5246 – RC4 broken
    TLS_RSA_WITH_RC4_128_SHA = 0x0005          # RFC 5246 – RC4 broken
    TLS_RSA_WITH_DES_CBC_SHA = 0x0009          # RFC 5469 – DES 56-bit broken
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000A    # SWEET32 (CVE-2016-2183)
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F      # Acceptable (no PFS)
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003D   # Better (no PFS)


# ---------------------------------------------------------------------------
# Handshake message types
# ---------------------------------------------------------------------------


class HandshakeType(enum.Enum):
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20


# ---------------------------------------------------------------------------
# BrokenTLSContext
# ---------------------------------------------------------------------------


class BrokenTLSContext:
    """
    TLS context object that can be configured with various security flaws.

    Analogous to Python's ``ssl.SSLContext`` but deliberately broken.

    Default configuration represents the worst possible settings:
    - No certificate verification
    - No hostname verification
    - Accept all protocol versions including SSL 2.0
    - Prefer NULL and RC4 cipher suites
    """

    def __init__(self):
        # VULNERABILITY (CWE-295): Certificate chain not verified
        self.verify_certificates = False

        # VULNERABILITY (CWE-297): Hostname not checked against cert CN/SAN
        self.check_hostname = False

        # VULNERABILITY: Accept every protocol version, even SSL 2.0
        self.minimum_version = ProtocolVersion.SSL_2_0
        self.maximum_version = ProtocolVersion.TLS_1_3

        # VULNERABILITY: Offer broken cipher suites in preference order
        self.cipher_suites: List[CipherSuiteID] = [
            CipherSuiteID.TLS_NULL_WITH_NULL_NULL,
            CipherSuiteID.TLS_RSA_WITH_NULL_MD5,
            CipherSuiteID.TLS_RSA_EXPORT_WITH_RC4_40_MD5,
            CipherSuiteID.TLS_RSA_WITH_RC4_128_MD5,
            CipherSuiteID.TLS_RSA_WITH_DES_CBC_SHA,
            CipherSuiteID.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        ]

        # VULNERABILITY: Session tickets without forward-secrecy key rotation
        self.session_tickets_enabled = True

        # VULNERABILITY: TLS compression enabled (CRIME attack, CVE-2012-4929)
        self.compression_enabled = True

    def get_vulnerability_report(self) -> List[dict]:
        """
        Return a list of vulnerability descriptions for the current context
        configuration.  Useful for classroom demonstrations.
        """
        findings = []

        if not self.verify_certificates:
            findings.append(
                {
                    "title": "Certificate verification disabled",
                    "cwe": "CWE-295",
                    "severity": "CRITICAL",
                    "description": (
                        "Without verifying the server certificate an attacker can "
                        "present any certificate and perform a MITM attack."
                    ),
                }
            )

        if not self.check_hostname:
            findings.append(
                {
                    "title": "Hostname verification disabled",
                    "cwe": "CWE-297",
                    "severity": "HIGH",
                    "description": (
                        "Even with a valid certificate an attacker can redirect "
                        "traffic using a certificate issued for a different domain."
                    ),
                }
            )

        broken_versions = {ProtocolVersion.SSL_2_0, ProtocolVersion.SSL_3_0}
        if self.minimum_version in broken_versions:
            findings.append(
                {
                    "title": "Broken protocol versions accepted",
                    "cve": "CVE-2014-3566 (POODLE), CVE-2016-0800 (DROWN)",
                    "severity": "CRITICAL",
                    "description": (
                        "SSL 2.0 and SSL 3.0 are cryptographically broken.  "
                        "Advertising support enables downgrade attacks."
                    ),
                }
            )

        vulnerable_suites = {
            CipherSuiteID.TLS_NULL_WITH_NULL_NULL: (
                "NULL cipher suite – data transmitted in plaintext"
            ),
            CipherSuiteID.TLS_RSA_WITH_NULL_MD5: (
                "NULL encryption cipher – no confidentiality"
            ),
            CipherSuiteID.TLS_RSA_EXPORT_WITH_RC4_40_MD5: (
                "FREAK (CVE-2015-0204) – 40-bit export key brute-forced in minutes"
            ),
            CipherSuiteID.TLS_RSA_WITH_RC4_128_MD5: (
                "RC4 – statistical biases enable plaintext recovery (CVE-2015-2808)"
            ),
            CipherSuiteID.TLS_RSA_WITH_RC4_128_SHA: (
                "RC4 – statistical biases enable plaintext recovery (CVE-2015-2808)"
            ),
            CipherSuiteID.TLS_RSA_WITH_DES_CBC_SHA: (
                "DES – 56-bit key exhaustively searched in ~24 h"
            ),
            CipherSuiteID.TLS_RSA_WITH_3DES_EDE_CBC_SHA: (
                "SWEET32 (CVE-2016-2183) – 3DES 64-bit blocks enable birthday attacks"
            ),
        }
        for suite in self.cipher_suites:
            if suite in vulnerable_suites:
                findings.append(
                    {
                        "title": f"Vulnerable cipher suite: {suite.name}",
                        "severity": "HIGH",
                        "description": vulnerable_suites[suite],
                    }
                )

        if self.compression_enabled:
            findings.append(
                {
                    "title": "TLS compression enabled",
                    "cve": "CVE-2012-4929 (CRIME)",
                    "severity": "HIGH",
                    "description": (
                        "When HTTP cookies are sent over a TLS connection with "
                        "compression, an attacker can recover secrets by observing "
                        "compressed ciphertext length changes."
                    ),
                }
            )

        return findings

    def create_handshake(self, hostname: str, port: int = 443) -> "BrokenTLSHandshake":
        """Create a handshake simulator for the given host."""
        return BrokenTLSHandshake(self, hostname, port)


# ---------------------------------------------------------------------------
# BrokenTLSHandshake
# ---------------------------------------------------------------------------


class BrokenTLSHandshake:
    """
    Simulates the TLS 1.2 handshake (RFC 5246 §7.3) with configurable flaws.

    No real network I/O occurs.  All message bytes are constructed in memory
    so students can inspect them with a hex editor or packet capture tool.

    Handshake flow::

        Client                         Server
        ------                         ------
        ClientHello        -->
                           <--        ServerHello
                           <--        Certificate
                           <--        ServerHelloDone
        ClientKeyExchange  -->
        ChangeCipherSpec   -->
        Finished           -->
                           <--        ChangeCipherSpec
                           <--        Finished
    """

    def __init__(self, context: BrokenTLSContext, hostname: str, port: int = 443):
        self.context = context
        self.hostname = hostname
        self.port = port

        self.client_random: Optional[bytes] = None
        self.server_random: Optional[bytes] = None
        self.negotiated_version: Optional[ProtocolVersion] = None
        self.negotiated_cipher: Optional[CipherSuiteID] = None
        self.master_secret: Optional[bytes] = None
        self._handshake_messages: List[tuple] = []

    # ------------------------------------------------------------------
    # Message construction
    # ------------------------------------------------------------------

    def create_client_hello(self) -> bytes:
        """
        Build a TLS ClientHello message advertising broken capabilities.

        VULNERABILITY – Downgrade attack: by advertising old protocol versions
        and weak cipher suites a server (or MITM) can force the connection to
        use broken cryptography even when both endpoints support TLS 1.3.
        """
        # VULNERABILITY (CVE-2008-0166): Weak PRNG – time-seeded LCG
        self.client_random = self._weak_random(32)

        version_bytes = self.context.minimum_version.to_bytes()

        # Cipher suites
        suite_bytes = b"".join(
            struct.pack(">H", s.value) for s in self.context.cipher_suites
        )
        suite_len = struct.pack(">H", len(suite_bytes))

        # Session ID
        session_id = b""

        # VULNERABILITY (CRIME, CVE-2012-4929): Advertise DEFLATE compression
        if self.context.compression_enabled:
            compression = bytes([2, 0x01, 0x00])  # length=2, DEFLATE, NULL
        else:
            compression = bytes([1, 0x00])  # length=1, NULL only

        body = (
            version_bytes
            + self.client_random
            + bytes([len(session_id)])
            + session_id
            + suite_len
            + suite_bytes
            + compression
        )

        msg = self._build_handshake_msg(HandshakeType.CLIENT_HELLO, body)
        self._handshake_messages.append(("CLIENT_HELLO", msg))
        return msg

    def simulate_server_hello(
        self,
        preferred_cipher: Optional[CipherSuiteID] = None,
    ) -> bytes:
        """
        Simulate a server that selects the *weakest* cipher offered.

        VULNERABILITY: A misconfigured or malicious server can negotiate the
        least-secure cipher from the client's advertised list.  Combined with
        a MITM who strips the TLS_FALLBACK_SCSV sentinel, this enables
        downgrade attacks.
        """
        self.server_random = os.urandom(32)

        # Select weakest advertised version
        self.negotiated_version = self.context.minimum_version

        # Select first (weakest) cipher from the client list
        if preferred_cipher:
            self.negotiated_cipher = preferred_cipher
        elif self.context.cipher_suites:
            self.negotiated_cipher = self.context.cipher_suites[0]
        else:
            self.negotiated_cipher = CipherSuiteID.TLS_NULL_WITH_NULL_NULL

        session_id = os.urandom(32)
        version_bytes = self.negotiated_version.to_bytes()

        # VULNERABILITY: DEFLATE compression selected
        compression = bytes([0x01]) if self.context.compression_enabled else bytes([0x00])

        body = (
            version_bytes
            + self.server_random
            + bytes([len(session_id)])
            + session_id
            + struct.pack(">H", self.negotiated_cipher.value)
            + compression
        )

        msg = self._build_handshake_msg(HandshakeType.SERVER_HELLO, body)
        self._handshake_messages.append(("SERVER_HELLO", msg))
        return msg

    def compute_master_secret(self, pre_master_secret: bytes) -> bytes:
        """
        Derive the 48-byte master secret.

        VULNERABILITY: SSL 3.0 uses MD5(secret || SHA1('A' * n || …)) instead
        of HMAC-based PRF.  The non-HMAC construction is weaker and enables
        certain key-recovery attacks.

        TLS 1.2 uses HMAC-SHA-256 based PRF (RFC 5246 §5).  TLS 1.3 uses
        HKDF (RFC 8446 §7.1).
        """
        if self.client_random is None or self.server_random is None:
            raise RuntimeError(
                "call create_client_hello() and simulate_server_hello() first"
            )

        seed = b"master secret" + self.client_random + self.server_random

        if self.negotiated_version in (ProtocolVersion.SSL_2_0, ProtocolVersion.SSL_3_0):
            # VULNERABILITY: SSL 3.0 non-HMAC PRF
            self.master_secret = self._ssl3_prf(pre_master_secret, seed, 48)
        else:
            # TLS 1.0–1.2 HMAC-based PRF (still not TLS 1.3's HKDF)
            self.master_secret = self._tls_prf(pre_master_secret, seed, 48)

        return self.master_secret

    def get_handshake_transcript(self) -> List[tuple]:
        """Return list of (label, raw_bytes) for each exchanged message."""
        return list(self._handshake_messages)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_handshake_msg(msg_type: HandshakeType, body: bytes) -> bytes:
        """Build a TLS Handshake message (RFC 5246 §7.4)."""
        length_3 = struct.pack(">I", len(body))[1:]  # 3-byte big-endian
        return bytes([msg_type.value]) + length_3 + body

    @staticmethod
    def _weak_random(length: int) -> bytes:
        """
        VULNERABILITY (CVE-2008-0166): Simulate the Debian OpenSSL weak-PRNG
        bug where only the process ID contributed to entropy.

        In the real bug only 15 bits of entropy were available, yielding
        ~32 768 possible 'random' values per key type.
        """
        seed = int(time.time()) & 0x7FFF  # 15 bits, like the Debian bug
        result = bytearray(length)
        state = seed
        for i in range(length):
            state = (state * 1103515245 + 12345) & 0x7FFFFFFF  # LCG
            result[i] = state & 0xFF
        return bytes(result)

    @staticmethod
    def _ssl3_prf(secret: bytes, seed: bytes, length: int) -> bytes:
        """SSL 3.0 pseudo-random function (non-HMAC – RFC 6101 §6)."""
        result = bytearray()
        counter = 1
        while len(result) < length:
            letter = chr(64 + counter).encode() * counter  # 'A', 'BB', 'CCC'…
            sha1_out = hashlib.sha1(letter + secret + seed).digest()
            md5_out = hashlib.md5(secret + sha1_out).digest()
            result.extend(md5_out)
            counter += 1
        return bytes(result[:length])

    @staticmethod
    def _tls_prf(secret: bytes, seed: bytes, length: int) -> bytes:
        """
        TLS 1.0/1.1 PRF = P_MD5(S1, label+seed) XOR P_SHA1(S2, label+seed).

        VULNERABILITY: Combining MD5 and SHA-1 is stronger than SSL 3.0 but
        weaker than TLS 1.2's HMAC-SHA-256 PRF.
        """
        half = (len(secret) + 1) // 2
        s1, s2 = secret[:half], secret[half:]

        def p_hash(hash_fn, s, seed, n):
            result = bytearray()
            a = hmac_digest(hash_fn, s, seed)  # A(1)
            while len(result) < n:
                result.extend(hmac_digest(hash_fn, s, a + seed))
                a = hmac_digest(hash_fn, s, a)  # A(i+1)
            return bytes(result[:n])

        def hmac_digest(hash_fn, key, data):
            import hmac as hmac_mod
            return hmac_mod.new(key, data, hash_fn).digest()

        p_md5 = p_hash(hashlib.md5, s1, seed, length)
        p_sha1 = p_hash(hashlib.sha1, s2, seed, length)
        return bytes(a ^ b for a, b in zip(p_md5, p_sha1))
