"""
Experimental (Broken) SSL Implementation
=========================================

EDUCATIONAL PURPOSES ONLY
--------------------------
This module is a rough draft / teaching aid that intentionally reproduces
the weaknesses found in real-world SSL 2.0 / 3.0 deployments.

DO NOT USE IN PRODUCTION.  It is deliberately insecure.

Known weaknesses demonstrated:
  * SSL 3.0 version (POODLE vulnerability – CVE-2014-3566)
  * RC4 stream cipher (broken – RC4 NOMORE, biased key-stream)
  * MD5 MAC (broken – collision attacks, length-extension)
  * NULL cipher suite (no encryption at all)
  * Export-grade 40-bit RC4 (FREAK-style key)
  * Deflate compression (CRIME attack – CVE-2012-4929)
  * MAC-then-Encrypt (Lucky13 / padding oracle)
  * No certificate verification
  * No sequence numbers in MAC (replay attacks)
  * Hardcoded fallback keys
  * Timestamp in client random (information leak)
  * Predictable pre-master secret structure
  * SSL 3.0 PRF that mixes MD5 + SHA-1 (SLOTH attack)
"""

import hashlib
import os
import struct
import time

# ---------------------------------------------------------------------------
# SSL Record Content Types (RFC 6101)
# ---------------------------------------------------------------------------
CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20
CONTENT_TYPE_ALERT = 21
CONTENT_TYPE_HANDSHAKE = 22
CONTENT_TYPE_APPLICATION_DATA = 23

# ---------------------------------------------------------------------------
# SSL Protocol Versions
# ---------------------------------------------------------------------------
SSL_VERSION_2_0 = 0x0002  # SSL 2.0 – completely broken
SSL_VERSION_3_0 = 0x0300  # SSL 3.0 – POODLE vulnerable

# ---------------------------------------------------------------------------
# Handshake Message Types (RFC 6101 §5.6)
# ---------------------------------------------------------------------------
HANDSHAKE_CLIENT_HELLO = 1
HANDSHAKE_SERVER_HELLO = 2
HANDSHAKE_CERTIFICATE = 11
HANDSHAKE_SERVER_HELLO_DONE = 14
HANDSHAKE_CLIENT_KEY_EXCHANGE = 16
HANDSHAKE_FINISHED = 20

# ---------------------------------------------------------------------------
# Cipher Suites – intentionally weak
# ---------------------------------------------------------------------------
SSL_NULL_WITH_NULL_NULL = 0x0000          # No encryption, no MAC
SSL_RSA_WITH_NULL_MD5 = 0x0001           # No encryption, MD5 only
SSL_RSA_WITH_NULL_SHA = 0x0002           # No encryption, SHA-1 only
SSL_RSA_EXPORT_WITH_RC4_40_MD5 = 0x0003  # 40-bit export RC4 + MD5
SSL_RSA_WITH_RC4_128_MD5 = 0x0004        # RC4-128 + MD5 (both broken)
SSL_RSA_WITH_DES_CBC_SHA = 0x0009        # DES-CBC (56-bit, broken)
SSL_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0008  # 40-bit export DES (very broken)

# ---------------------------------------------------------------------------
# Compression Methods
# ---------------------------------------------------------------------------
COMPRESSION_NULL = 0
COMPRESSION_DEFLATE = 1  # CRIME attack vector


# ---------------------------------------------------------------------------
# Broken primitives
# ---------------------------------------------------------------------------

def broken_rc4(key: bytes, data: bytes) -> bytes:
    """
    RC4 stream cipher.

    VULNERABILITY: RC4 is cryptographically broken.
      - First bytes of the key-stream are statistically biased.
      - WEP, WPA-TKIP, SSL 3.0 RC4 sessions are all attackable.
      - CVE-2013-2566 / CVE-2015-2808 (RC4 NOMORE).
    """
    S = list(range(256))
    j = 0
    key_bytes = list(key)
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)


def broken_mac(key: bytes, data: bytes) -> bytes:
    """
    Message Authentication Code using raw MD5.

    VULNERABILITY: MD5 is cryptographically broken.
      - Collision attacks (Wang et al., 2004).
      - Length-extension attack: MD5(key || data) leaks key material.
      - Proper code would use HMAC-SHA-256.
    """
    # VULNERABILITY: Simple concatenation, not HMAC
    return hashlib.md5(key + data).digest()


# ---------------------------------------------------------------------------
# Record layer
# ---------------------------------------------------------------------------

class SSLRecord:
    """
    SSL Record Layer packet.

    Structure (RFC 6101 §5.2):
        content_type  : 1 byte
        version_major : 1 byte
        version_minor : 1 byte
        length        : 2 bytes (big-endian)
        payload       : <length> bytes
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
    def unpack(cls, raw: bytes) -> 'SSLRecord':
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

class BrokenSSLHandshake:
    """
    Experimental SSL 3.0 handshake.

    Intentional weaknesses (see module docstring for full list).
    """

    def __init__(self):
        # VULNERABILITY: Advertising SSL 3.0 (POODLE)
        self.version = SSL_VERSION_3_0

        # VULNERABILITY: Null cipher suite is first (server may pick it)
        self.cipher_suites = [
            SSL_NULL_WITH_NULL_NULL,
            SSL_RSA_EXPORT_WITH_RC4_40_MD5,
            SSL_RSA_WITH_RC4_128_MD5,
            SSL_RSA_WITH_DES_CBC_SHA,
        ]

        # VULNERABILITY: Offering deflate compression (CRIME)
        self.compression_methods = [COMPRESSION_NULL, COMPRESSION_DEFLATE]

        self.session_id: bytes = b''
        self.client_random: bytes = b''
        self.server_random: bytes = b''
        self.master_secret: bytes = b''

        # Internal transcript for Finished hash
        self._transcript: bytes = b''

    # ------------------------------------------------------------------
    # ClientHello
    # ------------------------------------------------------------------

    def create_client_hello(self) -> bytes:
        """
        Build a ClientHello handshake message.

        VULNERABILITY: First 4 bytes of client_random are a UNIX timestamp
        (information leak – narrows brute-force window).
        VULNERABILITY: No TLS_FALLBACK_SCSV – allows version downgrade.
        """
        # VULNERABILITY: Timestamp in random
        client_random = struct.pack('!I', int(time.time())) + os.urandom(28)
        self.client_random = client_random

        cipher_data = struct.pack('!H', len(self.cipher_suites) * 2)
        for cs in self.cipher_suites:
            cipher_data += struct.pack('!H', cs)

        comp_data = bytes([len(self.compression_methods)] +
                          self.compression_methods)

        session_data = bytes([len(self.session_id)]) + self.session_id

        body = struct.pack('!H', self.version)
        body += client_random
        body += session_data
        body += cipher_data
        body += comp_data

        msg = self._wrap_handshake(HANDSHAKE_CLIENT_HELLO, body)
        self._transcript += msg
        return msg

    # ------------------------------------------------------------------
    # ServerHello
    # ------------------------------------------------------------------

    def create_server_hello(self) -> bytes:
        """
        Build a ServerHello handshake message.

        VULNERABILITY: Always selects the *weakest* cipher suite offered
        (first in the list = NULL cipher – no encryption at all).
        VULNERABILITY: Always selects deflate compression (CRIME).
        """
        server_random = struct.pack('!I', int(time.time())) + os.urandom(28)
        self.server_random = server_random

        # VULNERABILITY: Pick weakest cipher (index 0 = NULL)
        chosen_cipher = self.cipher_suites[0]
        # VULNERABILITY: Pick deflate compression (CRIME attack)
        chosen_compression = COMPRESSION_DEFLATE

        session_id = os.urandom(32)

        body = struct.pack('!H', self.version)
        body += server_random
        body += bytes([len(session_id)]) + session_id
        body += struct.pack('!H', chosen_cipher)
        body += bytes([chosen_compression])

        msg = self._wrap_handshake(HANDSHAKE_SERVER_HELLO, body)
        self._transcript += msg
        return msg

    # ------------------------------------------------------------------
    # Master secret / PRF
    # ------------------------------------------------------------------

    def compute_master_secret(self, pre_master_secret: bytes) -> bytes:
        """
        Compute the SSL 3.0 master secret.

        VULNERABILITY: Uses MD5 + SHA-1 concatenation PRF (SLOTH attack).
        VULNERABILITY: Does not bind the negotiated version into the PRF
        properly – version rollback goes undetected.
        """
        seed = self.client_random + self.server_random
        self.master_secret = self._prf_ssl3(pre_master_secret, seed, 48)
        return self.master_secret

    def _prf_ssl3(self, secret: bytes, seed: bytes, length: int) -> bytes:
        """
        SSL 3.0 PRF: repeated (MD5(secret || SHA1(label || seed))).

        VULNERABILITY: Uses MD5 (broken) as outer hash.
        VULNERABILITY: Fixed ASCII labels ('A', 'BB', 'CCC', ...) are
        trivially predictable.
        """
        result = b''
        i = 0
        while len(result) < length:
            i += 1
            label = bytes([0x41 + i - 1]) * i  # 'A', 'BB', 'CCC', ...
            sha_inner = hashlib.sha1(secret + label + seed).digest()
            md5_outer = hashlib.md5(secret + sha_inner).digest()
            result += md5_outer
        return result[:length]

    # ------------------------------------------------------------------
    # Encryption / MAC
    # ------------------------------------------------------------------

    def encrypt(self, data: bytes, key: bytes = b'') -> bytes:
        """
        Encrypt with RC4.

        VULNERABILITY: RC4 is broken (biased key-stream, NOMORE attack).
        VULNERABILITY: No separation of client/server keys.
        """
        if not key:
            key = self.master_secret[:16] if self.master_secret else b'\x00' * 16
        return broken_rc4(key, data)

    def decrypt(self, data: bytes, key: bytes = b'') -> bytes:
        """RC4 is symmetric; decryption == encryption."""
        return self.encrypt(data, key)

    def compute_mac(self, data: bytes, mac_key: bytes = b'') -> bytes:
        """
        Compute a MAC for the given data.

        VULNERABILITY: Uses raw MD5(key || data), not HMAC.
        VULNERABILITY: No sequence number included – replay attacks possible.
        """
        if not mac_key:
            mac_key = b'\x00' * 16
        return broken_mac(mac_key, data)

    # ------------------------------------------------------------------
    # Finished
    # ------------------------------------------------------------------

    def create_finished(self) -> bytes:
        """
        Build the SSL 3.0 Finished message.

        VULNERABILITY: Uses MD5 + SHA-1 of handshake transcript (SLOTH).
        VULNERABILITY: Only 36 bytes of verify_data (smaller than TLS 1.2's
        HMAC-SHA-256).
        """
        if not self.master_secret:
            self.master_secret = b'\x00' * 48

        # SSL 3.0 Finished = MD5(master || 'CLNT' || transcript) ||
        #                     SHA1(master || 'CLNT' || transcript)
        md5 = hashlib.md5(
            self.master_secret + b'CLNT' + self._transcript
        ).digest()
        sha1 = hashlib.sha1(
            self.master_secret + b'CLNT' + self._transcript
        ).digest()
        verify_data = md5 + sha1

        return self._wrap_handshake(HANDSHAKE_FINISHED, verify_data)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _wrap_handshake(msg_type: int, body: bytes) -> bytes:
        """Wrap body in a 4-byte handshake header (type + 3-byte length)."""
        length_bytes = struct.pack('!I', len(body))[1:]  # 3 bytes
        return bytes([msg_type]) + length_bytes + body


# ---------------------------------------------------------------------------
# High-level connection object
# ---------------------------------------------------------------------------

class BrokenSSLConnection:
    """
    Simulated broken SSL connection.

    Wraps BrokenSSLHandshake and provides send()/receive() helpers that
    demonstrate MAC-then-Encrypt and replay-attack weaknesses.
    """

    def __init__(self, is_server: bool = False):
        self.is_server = is_server
        self.handshake = BrokenSSLHandshake()
        self.handshake_complete = False

        # VULNERABILITY: Hardcoded fallback keys
        self._session_key: bytes = b'hardcoded_key_12'
        self._mac_key: bytes = b'mac_key_here_xxx'
        self._sequence_number: int = 0  # not used in MAC = replay attack

    # ------------------------------------------------------------------

    def do_handshake(self) -> dict:
        """
        Perform a simulated SSL handshake (client + server in-process).

        Returns a dict of all raw handshake messages for inspection.
        """
        client_hello = self.handshake.create_client_hello()
        server_hello = self.handshake.create_server_hello()

        # VULNERABILITY: Pre-master secret uses only os.urandom (no RSA)
        # VULNERABILITY: Version bytes are not verified by the server
        pre_master = struct.pack('!H', SSL_VERSION_3_0) + os.urandom(46)
        self.handshake.compute_master_secret(pre_master)

        # Derive session / MAC keys from master secret
        # VULNERABILITY: Same master secret used for both directions
        self._session_key = self.handshake.master_secret[:16]
        self._mac_key = self.handshake.master_secret[16:32]

        finished = self.handshake.create_finished()
        self.handshake_complete = True

        return {
            'client_hello': client_hello,
            'server_hello': server_hello,
            'pre_master_secret': pre_master,
            'master_secret': self.handshake.master_secret,
            'finished': finished,
        }

    # ------------------------------------------------------------------

    def send(self, data: bytes) -> bytes:
        """
        Encrypt and frame application data.

        VULNERABILITY: MAC-then-Encrypt order (Lucky13 / padding oracle).
        VULNERABILITY: No sequence number in MAC (replay attacks).
        VULNERABILITY: RC4 key-stream bias on first bytes.
        """
        if not self.handshake_complete:
            raise RuntimeError("Handshake not complete")

        # VULNERABILITY: MAC-then-Encrypt
        mac = self.handshake.compute_mac(data, self._mac_key)
        encrypted = self.handshake.encrypt(data + mac, self._session_key)

        record = SSLRecord(
            CONTENT_TYPE_APPLICATION_DATA,
            SSL_VERSION_3_0,
            encrypted,
        )
        self._sequence_number += 1
        return record.pack()

    def receive(self, raw: bytes) -> bytes:
        """
        Decrypt and verify received application data.

        VULNERABILITY: No sequence number check (replay attacks).
        VULNERABILITY: Non-constant-time MAC comparison (timing oracle).
        """
        record = SSLRecord.unpack(raw)
        decrypted = self.handshake.decrypt(record.data, self._session_key)

        if len(decrypted) < 16:
            raise ValueError("Record too short to contain MAC")

        data = decrypted[:-16]
        received_mac = decrypted[-16:]

        # VULNERABILITY: Non-constant-time comparison
        computed_mac = self.handshake.compute_mac(data, self._mac_key)
        if received_mac != computed_mac:
            raise ValueError("MAC verification failed")  # timing leak

        return data
