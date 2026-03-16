"""
Experimental (Broken) TLS Implementation
==========================================

EDUCATIONAL PURPOSES ONLY
--------------------------
This module is a rough draft / teaching aid that intentionally reproduces
the weaknesses found in real-world TLS 1.0 / 1.1 deployments.

DO NOT USE IN PRODUCTION.  It is deliberately insecure.

Known weaknesses demonstrated:
  * TLS 1.0 – BEAST attack (CBC with chained/predictable IV – CVE-2011-3389)
  * Predictable IV reuse (last ciphertext block becomes next record's IV)
  * AES-CBC simulated with XOR (trivially breakable – educational only)
  * MAC-then-Encrypt (Lucky13 – CVE-2013-0169)
  * Padding oracle (POODLE-style – CVE-2014-3566)
  * Non-constant-time MAC comparison (timing oracle)
  * RC4 cipher suite support (RC4 NOMORE – CVE-2015-2808)
  * 3DES cipher suite (SWEET32 – CVE-2016-2183)
  * Export-grade 40-bit cipher suite (FREAK – CVE-2015-0204)
  * NULL cipher suite (no encryption at all)
  * Deflate compression (CRIME – CVE-2012-4929)
  * No certificate chain verification
  * No OCSP / CRL revocation checking
  * No SNI validation
  * RSA key exchange with no forward secrecy (ROBOT – CVE-2017-13099)
  * Pre-master secret sent in the clear (conceptual demonstration)
  * TLS 1.0 PRF mixing MD5 + SHA-1 (SLOTH – CVE-2015-7575)
  * Timestamp in client_random (information leak)
  * No TLS_FALLBACK_SCSV (downgrade attack – CVE-2014-3568)
  * Unsafe renegotiation (CVE-2009-3555)
  * Hardcoded fallback keys
"""

import hashlib
import hmac as _hmac
import os
import struct
import time

# ---------------------------------------------------------------------------
# TLS Record Content Types (RFC 5246 §6.2.1)
# ---------------------------------------------------------------------------
TLS_CONTENT_CHANGE_CIPHER_SPEC = 20
TLS_CONTENT_ALERT = 21
TLS_CONTENT_HANDSHAKE = 22
TLS_CONTENT_APPLICATION_DATA = 23

# ---------------------------------------------------------------------------
# TLS Protocol Versions
# ---------------------------------------------------------------------------
TLS_VERSION_1_0 = 0x0301  # BEAST-vulnerable
TLS_VERSION_1_1 = 0x0302  # Less vulnerable but still weak
TLS_VERSION_1_2 = 0x0303  # Reasonable when configured correctly
SSL_VERSION_3_0 = 0x0300  # Included for downgrade demonstration

# ---------------------------------------------------------------------------
# Handshake Message Types (RFC 5246 §7.4)
# ---------------------------------------------------------------------------
TLS_HANDSHAKE_HELLO_REQUEST = 0
TLS_HANDSHAKE_CLIENT_HELLO = 1
TLS_HANDSHAKE_SERVER_HELLO = 2
TLS_HANDSHAKE_CERTIFICATE = 11
TLS_HANDSHAKE_SERVER_KEY_EXCHANGE = 12
TLS_HANDSHAKE_CERTIFICATE_REQUEST = 13
TLS_HANDSHAKE_SERVER_HELLO_DONE = 14
TLS_HANDSHAKE_CERTIFICATE_VERIFY = 15
TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE = 16
TLS_HANDSHAKE_FINISHED = 20

# ---------------------------------------------------------------------------
# Cipher Suites – intentionally weak selection
# ---------------------------------------------------------------------------
TLS_NULL_WITH_NULL_NULL = 0x0000           # No encryption, no MAC
TLS_RSA_WITH_NULL_MD5 = 0x0001            # No encryption, MD5 only
TLS_RSA_WITH_NULL_SHA = 0x0002            # No encryption, SHA-1 only
TLS_RSA_EXPORT_WITH_RC4_40_MD5 = 0x0003   # FREAK: 40-bit export RC4
TLS_RSA_WITH_RC4_128_MD5 = 0x0004         # RC4-128 + MD5 (both broken)
TLS_RSA_WITH_RC4_128_SHA = 0x0005         # RC4-128 + SHA-1 (RC4 broken)
TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000A    # 3DES-CBC (SWEET32 attack)
TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F     # AES-128-CBC + SHA-1 (BEAST)

# ---------------------------------------------------------------------------
# Alert Levels / Descriptions
# ---------------------------------------------------------------------------
TLS_ALERT_LEVEL_WARNING = 1
TLS_ALERT_LEVEL_FATAL = 2
TLS_ALERT_CLOSE_NOTIFY = 0
TLS_ALERT_UNEXPECTED_MESSAGE = 10
TLS_ALERT_HANDSHAKE_FAILURE = 40

# Block size used by the simulated cipher
_BLOCK_SIZE = 16


# ---------------------------------------------------------------------------
# Broken primitives
# ---------------------------------------------------------------------------

def _xor_blocks(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def broken_aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """
    Simulated AES-CBC encryption.

    VULNERABILITY: 'AES' is replaced with a single-round XOR against the key.
    Anyone who knows the key can trivially decrypt in O(n).

    VULNERABILITY: PKCS#7 padding + CBC + MAC-then-Encrypt = padding oracle
    (Lucky13 / POODLE).

    VULNERABILITY: When called repeatedly with iv = last_ciphertext_block
    (TLS 1.0 behaviour), the IV is predictable = BEAST attack.
    """
    # PKCS#7 padding
    pad_len = _BLOCK_SIZE - (len(plaintext) % _BLOCK_SIZE)
    padded = plaintext + bytes([pad_len] * pad_len)

    result = bytearray()
    prev = iv
    for i in range(0, len(padded), _BLOCK_SIZE):
        block = padded[i:i + _BLOCK_SIZE]
        chained = _xor_blocks(block, prev)
        # VULNERABILITY: "AES" is just XOR with key (not real AES)
        encrypted_block = _xor_blocks(chained, key[:_BLOCK_SIZE])
        result.extend(encrypted_block)
        prev = bytes(encrypted_block)

    return bytes(result)


def broken_aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Simulated AES-CBC decryption.

    VULNERABILITY: Same XOR-as-AES weakness as encryption.
    VULNERABILITY: Padding is removed silently without constant-time
    verification – classic padding oracle.
    """
    result = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), _BLOCK_SIZE):
        block = ciphertext[i:i + _BLOCK_SIZE]
        # VULNERABILITY: "AES" is just XOR with key
        decrypted_block = _xor_blocks(block, key[:_BLOCK_SIZE])
        xored = _xor_blocks(decrypted_block, prev)
        result.extend(xored)
        prev = block

    # VULNERABILITY: Only checks last padding byte (trivial oracle)
    if result:
        pad_len = result[-1]
        if 1 <= pad_len <= _BLOCK_SIZE:
            result = result[:-pad_len]

    return bytes(result)


# ---------------------------------------------------------------------------
# Record layer
# ---------------------------------------------------------------------------

class TLSRecord:
    """
    TLS Record Layer packet (RFC 5246 §6.2).

    Structure:
        content_type  : 1 byte
        version_major : 1 byte
        version_minor : 1 byte
        length        : 2 bytes (big-endian)
        payload       : <length> bytes

    VULNERABILITY: No per-record sequence number embedded in ciphertext
    (TLS 1.0/1.1) – replay attacks inside a session are possible.
    """

    def __init__(self, content_type: int, version: int, data: bytes):
        self.content_type = content_type
        self.version = version
        self.data = data

    def pack(self) -> bytes:
        major = (self.version >> 8) & 0xFF
        minor = self.version & 0xFF
        return struct.pack('!BBB', self.content_type, major, minor) + \
               struct.pack('!H', len(self.data)) + \
               self.data

    @classmethod
    def unpack(cls, raw: bytes) -> 'TLSRecord':
        if len(raw) < 5:
            raise ValueError("Record too short")
        content_type = raw[0]
        version = (raw[1] << 8) | raw[2]
        length = struct.unpack('!H', raw[3:5])[0]
        payload = raw[5:5 + length]
        return cls(content_type, version, payload)


# ---------------------------------------------------------------------------
# Handshake
# ---------------------------------------------------------------------------

class BrokenTLSHandshake:
    """
    Experimental TLS 1.0 handshake.

    Intentional weaknesses (see module docstring for full list).
    """

    def __init__(self):
        # VULNERABILITY: TLS 1.0 (BEAST-vulnerable CBC)
        self.version = TLS_VERSION_1_0

        # VULNERABILITY: Null + export-grade + RC4 + 3DES all offered
        self.supported_cipher_suites = [
            TLS_NULL_WITH_NULL_NULL,
            TLS_RSA_EXPORT_WITH_RC4_40_MD5,
            TLS_RSA_WITH_RC4_128_MD5,
            TLS_RSA_WITH_RC4_128_SHA,
            TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_RSA_WITH_AES_128_CBC_SHA,
        ]

        # VULNERABILITY: Deflate compression offered first (CRIME)
        self.compression_methods = [0x01, 0x00]  # deflate, null

        self.client_random: bytes = b''
        self.server_random: bytes = b''
        self.master_secret: bytes = b''
        self.session_id: bytes = b''

        self._transcript: bytes = b''

    # ------------------------------------------------------------------
    # ClientHello
    # ------------------------------------------------------------------

    def create_client_hello(self) -> bytes:
        """
        Build a TLS ClientHello.

        VULNERABILITY: Timestamp in first 4 bytes of client_random
        (information leak).
        VULNERABILITY: No TLS_FALLBACK_SCSV extension – downgrade attacks
        possible.
        VULNERABILITY: No renegotiation_info extension (CVE-2009-3555).
        """
        # VULNERABILITY: Timestamp leaks wall-clock time to attacker
        self.client_random = struct.pack('!I', int(time.time())) + os.urandom(28)

        cipher_data = struct.pack('!H', len(self.supported_cipher_suites) * 2)
        for cs in self.supported_cipher_suites:
            cipher_data += struct.pack('!H', cs)

        comp_data = bytes([len(self.compression_methods)] +
                          self.compression_methods)

        body = struct.pack('!H', self.version)
        body += self.client_random
        body += bytes([len(self.session_id)]) + self.session_id
        body += cipher_data
        body += comp_data
        # VULNERABILITY: No extensions – no SNI, no ALPN, no renegotiation info

        msg = self._wrap(TLS_HANDSHAKE_CLIENT_HELLO, body)
        self._transcript += msg
        return msg

    # ------------------------------------------------------------------
    # ServerHello
    # ------------------------------------------------------------------

    def create_server_hello(self) -> bytes:
        """
        Build a TLS ServerHello.

        VULNERABILITY: Always picks the weakest (first) cipher suite
        – NULL cipher = no encryption.
        VULNERABILITY: Picks deflate compression (CRIME attack).
        """
        self.server_random = struct.pack('!I', int(time.time())) + os.urandom(28)

        # VULNERABILITY: Weakest cipher wins
        chosen_cipher = self.supported_cipher_suites[0]  # NULL
        # VULNERABILITY: Deflate compression (CRIME)
        chosen_compression = self.compression_methods[0]  # 0x01 deflate

        session_id = os.urandom(32)

        body = struct.pack('!H', self.version)
        body += self.server_random
        body += bytes([len(session_id)]) + session_id
        body += struct.pack('!H', chosen_cipher)
        body += bytes([chosen_compression])

        msg = self._wrap(TLS_HANDSHAKE_SERVER_HELLO, body)
        self._transcript += msg
        return msg

    # ------------------------------------------------------------------
    # Certificate (fake / self-signed)
    # ------------------------------------------------------------------

    def create_fake_certificate(self) -> bytes:
        """
        Emit a placeholder certificate message.

        VULNERABILITY: Self-signed certificate with no CA chain.
        VULNERABILITY: No CRL or OCSP check.
        VULNERABILITY: Certificate content is completely fake (demo only).
        VULNERABILITY: No hostname / CN verification.
        """
        # Fake DER-encoded certificate bytes (not a real ASN.1 structure)
        fake_cert = (
            b'\x30\x82'                                        # SEQUENCE tag
            b'\x02\x01\x00'                                    # version
            b'FAKE_CERTIFICATE_FOR_EDUCATIONAL_PURPOSES_ONLY'  # subject/key
            + b'\x00' * 64                                     # padding
        )

        # Certificate message: 3-byte total list length + 3-byte cert length + cert
        cert_length_bytes = struct.pack('!I', len(fake_cert))[1:]
        list_length_bytes = struct.pack('!I', len(fake_cert) + 3)[1:]
        cert_msg_body = list_length_bytes + cert_length_bytes + fake_cert

        msg = self._wrap(TLS_HANDSHAKE_CERTIFICATE, cert_msg_body)
        self._transcript += msg
        return msg

    # ------------------------------------------------------------------
    # ServerHelloDone
    # ------------------------------------------------------------------

    def create_server_hello_done(self) -> bytes:
        """Build ServerHelloDone (empty body)."""
        msg = self._wrap(TLS_HANDSHAKE_SERVER_HELLO_DONE, b'')
        self._transcript += msg
        return msg

    # ------------------------------------------------------------------
    # PRF
    # ------------------------------------------------------------------

    def _prf_tls10(self, secret: bytes, label: bytes,
                   seed: bytes, length: int) -> bytes:
        """
        TLS 1.0 / 1.1 PRF.

        VULNERABILITY: Splits secret and XORs P_MD5 with P_SHA1 (SLOTH).
        VULNERABILITY: Uses MD5 in P_MD5 (broken hash).
        """
        def _p_hash(hash_constructor, key: bytes, data: bytes,
                    n: int) -> bytes:
            result = b''
            a = data  # A(0) = seed
            while len(result) < n:
                a = _hmac.new(key, a, hash_constructor).digest()  # A(i)
                result += _hmac.new(key, a + data, hash_constructor).digest()
            return result[:n]

        label_seed = label + seed

        # VULNERABILITY: Splitting the secret weakens it when len is odd
        mid = (len(secret) + 1) // 2
        s1 = secret[:mid]
        s2 = secret[mid:]  # overlaps by one byte when len is odd

        p_md5 = _p_hash(hashlib.md5, s1, label_seed, length)
        p_sha1 = _p_hash(hashlib.sha1, s2, label_seed, length)
        return bytes(a ^ b for a, b in zip(p_md5, p_sha1))

    # ------------------------------------------------------------------
    # Master secret
    # ------------------------------------------------------------------

    def compute_master_secret(self, pre_master_secret: bytes) -> bytes:
        """
        Compute TLS master secret.

        VULNERABILITY: RSA key exchange provides no forward secrecy.
        VULNERABILITY: Bleichenbacher / ROBOT attack on RSA PKCS#1 v1.5
        padding means the pre-master secret can be recovered offline.
        VULNERABILITY: Version bytes in pre_master_secret are not verified
        here (version rollback).
        """
        seed = self.client_random + self.server_random
        self.master_secret = self._prf_tls10(
            pre_master_secret, b'master secret', seed, 48
        )
        return self.master_secret

    def compute_key_block(self, length: int = 128) -> bytes:
        """Derive key material from master secret."""
        seed = self.server_random + self.client_random
        return self._prf_tls10(
            self.master_secret, b'key expansion', seed, length
        )

    # ------------------------------------------------------------------
    # ClientKeyExchange
    # ------------------------------------------------------------------

    def create_client_key_exchange(self) -> bytes:
        """
        Build ClientKeyExchange.

        VULNERABILITY: RSA key exchange – no perfect forward secrecy.
        VULNERABILITY: Pre-master secret is transmitted in the clear here
        (in real TLS it would be RSA-encrypted, but that introduces ROBOT).
        VULNERABILITY: Version bytes not checked by server (rollback).
        """
        # VULNERABILITY: Using TLS_VERSION_1_0 in PMS (should match ClientHello)
        pre_master = struct.pack('!H', TLS_VERSION_1_0) + os.urandom(46)

        # VULNERABILITY: Sent in the clear – real RSA encryption omitted
        body = struct.pack('!H', len(pre_master)) + pre_master

        msg = self._wrap(TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE, body)
        self._transcript += msg

        self.compute_master_secret(pre_master)
        return msg

    # ------------------------------------------------------------------
    # Finished
    # ------------------------------------------------------------------

    def create_finished(self, sender: bytes) -> bytes:
        """
        Build a Finished message.

        VULNERABILITY: Uses MD5 + SHA-1 transcript hash (SLOTH).
        VULNERABILITY: Only 12 bytes of verify_data (minimum per spec).
        """
        if not self.master_secret:
            self.master_secret = b'\x00' * 48

        # Hash of transcript using both MD5 and SHA-1 (VULNERABILITY: SLOTH)
        transcript_hash = (
            hashlib.md5(self._transcript).digest() +
            hashlib.sha1(self._transcript).digest()
        )
        verify_data = self._prf_tls10(
            self.master_secret, sender, transcript_hash, 12
        )
        return self._wrap(TLS_HANDSHAKE_FINISHED, verify_data)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _wrap(msg_type: int, body: bytes) -> bytes:
        """Wrap body in a 4-byte handshake header (type + 3-byte length)."""
        return bytes([msg_type]) + struct.pack('!I', len(body))[1:] + body


# ---------------------------------------------------------------------------
# High-level connection object
# ---------------------------------------------------------------------------

class BrokenTLSConnection:
    """
    Simulated broken TLS connection.

    Wraps BrokenTLSHandshake and provides send()/receive() helpers that
    demonstrate BEAST, padding oracle, and timing oracle weaknesses.
    """

    def __init__(self, is_server: bool = False):
        self.is_server = is_server
        self.tls = BrokenTLSHandshake()
        self.handshake_complete = False

        # VULNERABILITY: Hardcoded fallback keys (used before handshake)
        self._enc_key: bytes = b'weak_enc_key_xxx'
        self._mac_key: bytes = b'weak_mac_key_xxx'

        # VULNERABILITY: All-zero static IV (BEAST attack in TLS 1.0)
        self._iv: bytes = b'\x00' * _BLOCK_SIZE

        self._send_seq: int = 0
        self._recv_seq: int = 0

    # ------------------------------------------------------------------

    def do_handshake(self) -> dict:
        """
        Perform a full (simulated) TLS handshake in-process.

        Returns a dict of raw handshake messages for inspection.
        """
        client_hello = self.tls.create_client_hello()
        server_hello = self.tls.create_server_hello()
        certificate = self.tls.create_fake_certificate()
        server_done = self.tls.create_server_hello_done()
        client_key_exchange = self.tls.create_client_key_exchange()

        # VULNERABILITY: No certificate verification before deriving keys

        client_finished = self.tls.create_finished(b'client finished')
        server_finished = self.tls.create_finished(b'server finished')

        if self.tls.master_secret:
            key_block = self.tls.compute_key_block()
            self._mac_key = key_block[:16]
            self._enc_key = key_block[16:32]
            # VULNERABILITY: IV taken from key block (static, not fresh per record)
            # TLS 1.1+ would use an explicit random IV per record
            self._iv = key_block[32:48]

        self.handshake_complete = True

        return {
            'client_hello': client_hello,
            'server_hello': server_hello,
            'certificate': certificate,
            'server_hello_done': server_done,
            'client_key_exchange': client_key_exchange,
            'client_finished': client_finished,
            'server_finished': server_finished,
            'master_secret': self.tls.master_secret,
        }

    # ------------------------------------------------------------------

    def send(self, data: bytes) -> bytes:
        """
        Encrypt and frame application data.

        VULNERABILITY: MAC-then-Encrypt (Lucky13 padding oracle).
        VULNERABILITY: IV = last ciphertext block (BEAST in TLS 1.0).
        VULNERABILITY: No sequence number in MAC (replay attacks).
        VULNERABILITY: MD5 HMAC (weak hash).
        """
        if not self.handshake_complete:
            raise RuntimeError("Handshake not complete")

        # VULNERABILITY: MAC-then-Encrypt (should be Encrypt-then-MAC)
        # VULNERABILITY: MD5 HMAC
        mac = _hmac.new(self._mac_key, data, hashlib.md5).digest()
        plaintext_with_mac = data + mac

        encrypted = broken_aes_cbc_encrypt(
            self._enc_key, self._iv, plaintext_with_mac
        )

        # VULNERABILITY: Chain IV from last ciphertext block (BEAST!)
        if len(encrypted) >= _BLOCK_SIZE:
            self._iv = encrypted[-_BLOCK_SIZE:]

        record = TLSRecord(
            TLS_CONTENT_APPLICATION_DATA,
            TLS_VERSION_1_0,
            encrypted,
        )
        self._send_seq += 1
        return record.pack()

    def receive(self, raw: bytes) -> bytes:
        """
        Decrypt and verify received application data.

        VULNERABILITY: No sequence number check (replay attacks).
        VULNERABILITY: Non-constant-time MAC comparison (timing oracle).
        VULNERABILITY: Different error paths for padding failure vs MAC
        failure (Lucky13 timing oracle – CVE-2013-0169).
        """
        record = TLSRecord.unpack(raw)
        decrypted = broken_aes_cbc_decrypt(self._enc_key, self._iv, record.data)

        if len(decrypted) < _HMAC_MD5_SIZE:
            # VULNERABILITY: Reveals record-too-short vs MAC-fail timing
            raise ValueError("Decrypted record too short")

        data = decrypted[:-_HMAC_MD5_SIZE]
        received_mac = decrypted[-_HMAC_MD5_SIZE:]

        # VULNERABILITY: Non-constant-time comparison
        computed_mac = _hmac.new(self._mac_key, data, hashlib.md5).digest()
        if received_mac != computed_mac:
            raise ValueError("Bad MAC")  # timing differs from padding error

        self._recv_seq += 1
        return data


_HMAC_MD5_SIZE = 16  # MD5 digest size in bytes
