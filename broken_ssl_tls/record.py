"""
Broken TLS Record Layer
========================

The TLS record layer wraps application data before it is sent over the wire.
This module demonstrates vulnerabilities in the record layer, including weak
MACs, padding oracles, and record fragmentation issues.

WARNING: Intentionally insecure – for educational purposes only.
"""

import hashlib
import hmac
import struct


class ContentType:
    """TLS ContentType values (RFC 5246 §6.2.1)."""

    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23


class BrokenMAC:
    """
    Demonstrates broken MAC (Message Authentication Code) constructions.

    VULNERABILITY: SSL 3.0 and early TLS versions used a non-standard
    MAC construction (MAC(key || pad1 || data || pad2)) that is vulnerable
    to length-extension attacks.  HMAC (RFC 2104) was introduced to fix
    this, but some implementations still used the broken version.
    """

    @staticmethod
    def ssl3_mac(key: bytes, data: bytes) -> bytes:
        """
        SSL 3.0 MAC construction.

        VULNERABILITY: This construction is not HMAC.  It does not provide
        the same security guarantees as HMAC(SHA-256) and is susceptible to
        length-extension attacks when used with MD5 or SHA-1.

        Reference: RFC 6101 §5.2.3
        """
        pad1 = b"\x36" * 40  # ipad
        pad2 = b"\x5c" * 40  # opad
        # Outer hash: SHA1(key || pad2 || SHA1(key || pad1 || data))
        inner = hashlib.sha1(key + pad1 + data).digest()
        outer = hashlib.sha1(key + pad2 + inner).digest()
        return outer

    @staticmethod
    def null_mac(key: bytes, data: bytes) -> bytes:
        """
        VULNERABILITY: No MAC at all.

        Matches TLS_NULL_WITH_NULL_NULL – without a MAC an attacker can
        silently modify application data in transit (no integrity protection).
        """
        return b""

    @staticmethod
    def truncated_hmac(key: bytes, data: bytes, length: int = 10) -> bytes:
        """
        VULNERABILITY: Truncated HMAC.

        RFC 4366 §3.7 allows truncating HMACs to 10 bytes to save bandwidth.
        A 10-byte (80-bit) MAC provides far less forgery resistance than a
        full 32-byte HMAC-SHA-256.  Combined with padding oracle attacks,
        truncated MACs reduce the work required for forgery.
        """
        full_mac = hmac.new(key, data, hashlib.sha1).digest()
        return full_mac[:length]


class BrokenTLSRecord:
    """
    TLS Record layer with intentional padding oracle vulnerability.

    VULNERABILITY (POODLE, CVE-2014-3566): SSL 3.0 did not verify the
    contents of CBC padding bytes—only the last byte (the padding length)
    was checked.  This allowed an attacker to use a chosen-plaintext /
    chosen-boundary attack to decrypt one byte of plaintext per ~256
    requests (the POODLE attack).

    TLS 1.0 fixed padding byte values but is still vulnerable to the BEAST
    attack (CVE-2011-3389) due to predictable IVs.

    This class simulates writing and reading TLS records so students can
    observe the structure and understand where the flaws lie.
    """

    HEADER_SIZE = 5  # content_type (1) + version (2) + length (2)

    def __init__(self, version: tuple = (3, 1), mac_fn=None, cipher=None):
        """
        Parameters
        ----------
        version : tuple
            (major, minor) protocol version bytes, e.g. (3, 0) for SSL 3.0.
        mac_fn : callable, optional
            MAC function with signature (key, data) -> bytes.
            Defaults to BrokenMAC.null_mac.
        cipher : object, optional
            Cipher object with .encrypt() / .decrypt() methods.
            Defaults to NullCipher (no encryption).
        """
        from .ciphers import NullCipher

        self.version = version
        self.mac_fn = mac_fn or BrokenMAC.null_mac
        self.cipher = cipher or NullCipher()
        self._seq_num = 0  # sequence number for MAC

    # ------------------------------------------------------------------
    # Writing records
    # ------------------------------------------------------------------

    def write_record(
        self,
        content_type: int,
        plaintext: bytes,
        mac_key: bytes = b"",
        cipher_key: bytes = b"",
    ) -> bytes:
        """
        Build a TLS record from plaintext application data.

        Structure (RFC 5246 §6.2)::

            struct {
                ContentType type;      // 1 byte
                ProtocolVersion version; // 2 bytes
                uint16 length;         // 2 bytes
                opaque fragment[TLSPlaintext.length];
            } TLSPlaintext;

        VULNERABILITY: In SSL 3.0 the MAC is computed *before* encryption
        (MAC-then-Encrypt) which enables padding oracle attacks.  TLS 1.3
        switched to Encrypt-then-MAC (or AEAD) to fix this.
        """
        # Step 1: Compute MAC over sequence_number || content_type || version || data
        seq_bytes = struct.pack(">Q", self._seq_num)
        mac_input = (
            seq_bytes
            + bytes([content_type])
            + bytes(self.version)
            + struct.pack(">H", len(plaintext))
            + plaintext
        )
        mac = self.mac_fn(mac_key, mac_input)

        # Step 2: Encrypt plaintext || MAC (MAC-then-Encrypt – broken order)
        payload = plaintext + mac
        encrypted = self.cipher.encrypt(payload, cipher_key)

        # Step 3: Build record header
        header = (
            bytes([content_type])
            + bytes(self.version)
            + struct.pack(">H", len(encrypted))
        )
        self._seq_num += 1
        return header + encrypted

    # ------------------------------------------------------------------
    # Reading records
    # ------------------------------------------------------------------

    def read_record(
        self, data: bytes, mac_key: bytes = b"", cipher_key: bytes = b""
    ) -> dict:
        """
        Parse a TLS record and return its components.

        VULNERABILITY (Lucky13, CVE-2013-0169): MAC verification timing is
        data-length-dependent in naive implementations.  An attacker can
        measure the time to distinguish valid from invalid padding, enabling
        a padding oracle even in TLS 1.2 when CBC mode is used.
        """
        if len(data) < self.HEADER_SIZE:
            raise ValueError("Record too short to contain a valid header.")

        content_type = data[0]
        version = (data[1], data[2])
        length = struct.unpack(">H", data[3:5])[0]
        encrypted_fragment = data[5 : 5 + length]

        # Decrypt
        decrypted = self.cipher.decrypt(encrypted_fragment, cipher_key)

        # Split plaintext and MAC
        mac_len = len(self.mac_fn(mac_key, b""))  # probe MAC length
        if mac_len > 0 and len(decrypted) >= mac_len:
            plaintext = decrypted[:-mac_len]
            received_mac = decrypted[-mac_len:]
        else:
            plaintext = decrypted
            received_mac = b""

        return {
            "content_type": content_type,
            "version": version,
            "plaintext": plaintext,
            "mac": received_mac,
            "raw_length": length,
        }

    def demonstrate_padding_oracle(self) -> str:
        """
        Explain the CBC padding oracle vulnerability in plain English.

        Returns a textual description that can be displayed to students.
        """
        return (
            "CBC Padding Oracle Vulnerability\n"
            "================================\n"
            "\n"
            "In SSL 3.0 / TLS 1.0 with CBC-mode ciphers:\n"
            "\n"
            "1. The server pads plaintext to a block boundary before encrypting.\n"
            "2. After decryption the server checks whether the padding is valid.\n"
            "3. If the server returns a different error for 'bad padding' vs\n"
            "   'bad MAC', an attacker can use this as an oracle to decrypt\n"
            "   ciphertext one byte at a time.\n"
            "\n"
            "POODLE (CVE-2014-3566) exploits this flaw in SSL 3.0 where\n"
            "padding bytes are never verified—only the count byte.\n"
            "\n"
            "Fix: Use TLS 1.3 with AEAD ciphers (AES-GCM, ChaCha20-Poly1305)\n"
            "which provide both encryption and integrity with no padding oracle."
        )
