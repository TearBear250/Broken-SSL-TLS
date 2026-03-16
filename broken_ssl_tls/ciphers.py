"""
Weak and Broken Cipher Implementations
=======================================

This module provides intentionally weak ciphers used in old or misconfigured
SSL/TLS deployments.  Each class is documented with the vulnerability it
demonstrates.

WARNING: Do NOT use these ciphers for real data protection.
"""

import hashlib
import struct


class NullCipher:
    """
    TLS_NULL_WITH_NULL_NULL (0x0000)

    VULNERABILITY: No encryption whatsoever.  Every byte of application data
    is transmitted in plaintext.  An attacker who can read the network can
    read every message without any effort.

    Present in RFC 5246 §A.5 as the mandatory baseline cipher suite.  Any
    server that *negotiates* this suite is catastrophically misconfigured.
    """

    name = "TLS_NULL_WITH_NULL_NULL"
    key_size = 0

    def encrypt(self, plaintext: bytes, _key: bytes = b"") -> bytes:
        """'Encrypt' by returning the plaintext unchanged."""
        return plaintext

    def decrypt(self, ciphertext: bytes, _key: bytes = b"") -> bytes:
        """'Decrypt' by returning the ciphertext unchanged."""
        return ciphertext

    def __repr__(self):
        return f"NullCipher(name={self.name!r})"


class RC4Cipher:
    """
    RC4 Stream Cipher (TLS_RSA_WITH_RC4_128_MD5 / TLS_RSA_WITH_RC4_128_SHA)

    VULNERABILITY: RC4 has well-known statistical biases in its keystream.
    Attacks such as the "Bar Mitzvah" attack (CVE-2015-2808) can recover
    plaintext bytes—especially HTTP cookies—after observing enough ciphertexts
    encrypted under the same key.

    RC4 was banned from TLS by RFC 7465 (2015).

    Reference: https://www.rc4nomore.com/
    """

    name = "RC4"
    key_size = 16  # 128-bit

    def _ksa(self, key: bytes) -> list:
        """Key Scheduling Algorithm."""
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        return S

    def _prga(self, S: list, length: int) -> bytes:
        """Pseudo-Random Generation Algorithm."""
        i = j = 0
        keystream = bytearray(length)
        for k in range(length):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            keystream[k] = S[(S[i] + S[j]) % 256]
        return bytes(keystream)

    def encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        """Encrypt using RC4 (XOR with keystream)."""
        S = self._ksa(key)
        keystream = self._prga(S, len(plaintext))
        return bytes(p ^ k for p, k in zip(plaintext, keystream))

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """Decrypt using RC4 (symmetric – identical to encrypt)."""
        return self.encrypt(ciphertext, key)

    def __repr__(self):
        return f"RC4Cipher(name={self.name!r}, key_size={self.key_size})"


class WeakExportCipher:
    """
    Export-Grade XOR Cipher (analogous to TLS_RSA_EXPORT_WITH_RC4_40_MD5)

    VULNERABILITY: US export regulations once limited symmetric keys to 40
    bits.  A 40-bit key has only 2^40 (~1 trillion) possible values, which
    can be exhaustively searched in minutes on modern hardware.

    This is the weakness exploited by the FREAK attack (CVE-2015-0204), where
    a man-in-the-middle could force a downgrade to export-grade ciphers and
    then brute-force the session key.

    Reference: https://freakattack.com/
    """

    name = "EXPORT_RC4_40"
    key_size = 5  # 40-bit key

    def _expand_key(self, key: bytes, length: int) -> bytes:
        """Expand a short key by repeating it (insecure key schedule)."""
        repeated = (key * ((length // len(key)) + 1))[:length]
        return repeated

    def encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        """Encrypt with a 40-bit key via repeating-XOR."""
        if len(key) != self.key_size:
            raise ValueError(f"Key must be exactly {self.key_size} bytes (40 bits).")
        expanded = self._expand_key(key, len(plaintext))
        return bytes(p ^ k for p, k in zip(plaintext, expanded))

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """Decrypt (symmetric with encrypt)."""
        return self.encrypt(ciphertext, key)

    def __repr__(self):
        return f"WeakExportCipher(name={self.name!r}, key_size={self.key_size})"


class DESCipher:
    """
    Simplified DES-like block cipher demonstrating 56-bit key weakness.

    VULNERABILITY: DES uses a 56-bit effective key size.  The entire keyspace
    can be exhaustively searched in roughly 24 hours using dedicated hardware
    (e.g. the EFF's "Deep Crack", 1998).  DES was deprecated and replaced by
    AES via NIST in 2002.

    This implementation is a simplified educational stand-in that highlights
    the short key as the core flaw rather than replicating all DES internals.
    """

    name = "DES_CBC"
    key_size = 7  # 56-bit (DES ignores the 8th bit of each of 8 bytes)
    block_size = 8

    def _pad(self, data: bytes) -> bytes:
        """PKCS#5/7 padding to block boundary."""
        pad_len = self.block_size - (len(data) % self.block_size)
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data: bytes) -> bytes:
        """Remove PKCS#5/7 padding."""
        if not data:
            return data
        pad_len = data[-1]
        return data[:-pad_len]

    def _xor_block(self, block: bytes, key: bytes) -> bytes:
        """XOR a block with the key (simplified round function)."""
        key_expanded = self._expand_key(key, len(block))
        return bytes(b ^ k for b, k in zip(block, key_expanded))

    def _expand_key(self, key: bytes, length: int) -> bytes:
        digest = hashlib.md5(key).digest()
        return (digest * ((length // 16) + 1))[:length]

    def encrypt(self, plaintext: bytes, key: bytes, iv: bytes = None) -> bytes:
        """
        Encrypt in CBC mode.

        VULNERABILITY (BEAST, CVE-2011-3389): In TLS 1.0 the IV for each
        record is the last ciphertext block of the previous record—predictable
        to an attacker who can observe traffic.  This implementation
        optionally accepts an explicit IV to demonstrate the issue.
        """
        if len(key) != self.key_size:
            raise ValueError(f"Key must be {self.key_size} bytes.")
        if iv is None:
            iv = b"\x00" * self.block_size  # VULNERABILITY: zero IV
        padded = self._pad(plaintext)
        ciphertext = bytearray()
        prev = iv
        for i in range(0, len(padded), self.block_size):
            block = padded[i : i + self.block_size]
            xored = bytes(b ^ p for b, p in zip(block, prev))
            encrypted = self._xor_block(xored, key)
            ciphertext.extend(encrypted)
            prev = encrypted
        return bytes(ciphertext)

    def decrypt(self, ciphertext: bytes, key: bytes, iv: bytes = None) -> bytes:
        """Decrypt in CBC mode."""
        if len(key) != self.key_size:
            raise ValueError(f"Key must be {self.key_size} bytes.")
        if iv is None:
            iv = b"\x00" * self.block_size
        plaintext = bytearray()
        prev = iv
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i : i + self.block_size]
            decrypted = self._xor_block(block, key)
            plaintext.extend(bytes(b ^ p for b, p in zip(decrypted, prev)))
            prev = block
        return self._unpad(bytes(plaintext))

    def __repr__(self):
        return f"DESCipher(name={self.name!r}, key_size={self.key_size * 8}-bit)"
