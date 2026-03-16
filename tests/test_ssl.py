"""
Tests for broken_ssl.py – Experimental (Broken) SSL Implementation.

These tests verify that the module's classes and functions behave as
described in their docstrings.  They are NOT security validation tests;
they confirm the educational demonstration works correctly (i.e. the
intentional weaknesses are exercised and observable).
"""

import struct
import unittest

from broken_ssl import (
    COMPRESSION_DEFLATE,
    COMPRESSION_NULL,
    CONTENT_TYPE_APPLICATION_DATA,
    HANDSHAKE_CLIENT_HELLO,
    HANDSHAKE_FINISHED,
    HANDSHAKE_SERVER_HELLO,
    SSL_NULL_WITH_NULL_NULL,
    SSL_RSA_WITH_RC4_128_MD5,
    SSL_VERSION_3_0,
    BrokenSSLConnection,
    BrokenSSLHandshake,
    SSLRecord,
    broken_mac,
    broken_rc4,
)


# ---------------------------------------------------------------------------
# Primitive tests
# ---------------------------------------------------------------------------

class TestBrokenRC4(unittest.TestCase):

    def test_known_vector(self):
        """RC4 with key b'Key' should encrypt b'Plaintext' to a known result."""
        key = b'Key'
        plaintext = b'Plaintext'
        # Known RC4 result for this key/plaintext pair
        expected = bytes([0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3])
        self.assertEqual(broken_rc4(key, plaintext), expected)

    def test_symmetric(self):
        """Applying RC4 twice with the same key must yield the original plaintext."""
        key = b'testkey'
        data = b'hello, broken SSL!'
        encrypted = broken_rc4(key, data)
        decrypted = broken_rc4(key, encrypted)
        self.assertEqual(decrypted, data)

    def test_different_keys_produce_different_ciphertext(self):
        key1 = b'key1'
        key2 = b'key2'
        data = b'same plaintext'
        self.assertNotEqual(broken_rc4(key1, data), broken_rc4(key2, data))

    def test_empty_input(self):
        self.assertEqual(broken_rc4(b'k', b''), b'')

    def test_single_byte(self):
        result = broken_rc4(b'k', b'\x00')
        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 1)


class TestBrokenMAC(unittest.TestCase):

    def test_produces_16_bytes(self):
        """MD5 digest is 16 bytes."""
        mac = broken_mac(b'key', b'data')
        self.assertEqual(len(mac), 16)

    def test_deterministic(self):
        mac1 = broken_mac(b'key', b'data')
        mac2 = broken_mac(b'key', b'data')
        self.assertEqual(mac1, mac2)

    def test_different_data_different_mac(self):
        self.assertNotEqual(broken_mac(b'k', b'a'), broken_mac(b'k', b'b'))

    def test_different_key_different_mac(self):
        self.assertNotEqual(broken_mac(b'k1', b'data'), broken_mac(b'k2', b'data'))

    def test_length_extension_weakness(self):
        """
        Demonstrate length-extension weakness: MD5(k||m1||m2) can be computed
        from MD5(k||m1) without knowing k.  Here we just verify the raw
        concatenation property that enables the attack.
        """
        key = b'secret'
        msg = b'amount=100'
        mac1 = broken_mac(key, msg)
        # An attacker can forge MAC for extended message using length-extension
        # (full exploit not implemented, but we verify the function is naive)
        import hashlib
        self.assertEqual(mac1, hashlib.md5(key + msg).digest())


# ---------------------------------------------------------------------------
# SSLRecord tests
# ---------------------------------------------------------------------------

class TestSSLRecord(unittest.TestCase):

    def test_pack_unpack_roundtrip(self):
        record = SSLRecord(CONTENT_TYPE_APPLICATION_DATA, SSL_VERSION_3_0, b'hello')
        packed = record.pack()
        recovered = SSLRecord.unpack(packed)
        self.assertEqual(recovered.content_type, record.content_type)
        self.assertEqual(recovered.version, record.version)
        self.assertEqual(recovered.data, record.data)

    def test_pack_format(self):
        """Pack should produce 5-byte header + payload."""
        payload = b'test'
        record = SSLRecord(CONTENT_TYPE_APPLICATION_DATA, SSL_VERSION_3_0, payload)
        packed = record.pack()
        self.assertEqual(len(packed), 5 + len(payload))

    def test_version_encoding(self):
        record = SSLRecord(CONTENT_TYPE_APPLICATION_DATA, SSL_VERSION_3_0, b'x')
        packed = record.pack()
        self.assertEqual(packed[1], 0x03)  # major
        self.assertEqual(packed[2], 0x00)  # minor

    def test_unpack_too_short_raises(self):
        with self.assertRaises(ValueError):
            SSLRecord.unpack(b'\x17\x03\x00')  # only 3 bytes

    def test_empty_payload(self):
        record = SSLRecord(CONTENT_TYPE_APPLICATION_DATA, SSL_VERSION_3_0, b'')
        packed = record.pack()
        recovered = SSLRecord.unpack(packed)
        self.assertEqual(recovered.data, b'')


# ---------------------------------------------------------------------------
# BrokenSSLHandshake tests
# ---------------------------------------------------------------------------

class TestBrokenSSLHandshake(unittest.TestCase):

    def setUp(self):
        self.hs = BrokenSSLHandshake()

    def test_client_hello_starts_with_type_byte(self):
        msg = self.hs.create_client_hello()
        self.assertEqual(msg[0], HANDSHAKE_CLIENT_HELLO)

    def test_client_hello_contains_version(self):
        msg = self.hs.create_client_hello()
        # Version is at bytes 4-5 of the body (after 1-byte type + 3-byte len)
        version = struct.unpack('!H', msg[4:6])[0]
        self.assertEqual(version, SSL_VERSION_3_0)

    def test_client_hello_stores_client_random(self):
        self.hs.create_client_hello()
        self.assertEqual(len(self.hs.client_random), 32)

    def test_server_hello_starts_with_type_byte(self):
        self.hs.create_client_hello()  # must be called first
        msg = self.hs.create_server_hello()
        self.assertEqual(msg[0], HANDSHAKE_SERVER_HELLO)

    def test_server_hello_stores_server_random(self):
        self.hs.create_client_hello()
        self.hs.create_server_hello()
        self.assertEqual(len(self.hs.server_random), 32)

    def test_compute_master_secret_length(self):
        self.hs.client_random = b'\xAA' * 32
        self.hs.server_random = b'\xBB' * 32
        pms = b'\x03\x00' + b'\xCC' * 46
        ms = self.hs.compute_master_secret(pms)
        self.assertEqual(len(ms), 48)

    def test_master_secret_deterministic(self):
        self.hs.client_random = b'\x01' * 32
        self.hs.server_random = b'\x02' * 32
        pms = b'\x03' * 48
        ms1 = self.hs.compute_master_secret(pms)
        self.hs.master_secret = b''
        ms2 = self.hs.compute_master_secret(pms)
        self.assertEqual(ms1, ms2)

    def test_encrypt_decrypt_roundtrip(self):
        key = b'k' * 16
        plaintext = b'secret message'
        ciphertext = self.hs.encrypt(plaintext, key)
        self.assertNotEqual(ciphertext, plaintext)
        recovered = self.hs.decrypt(ciphertext, key)
        self.assertEqual(recovered, plaintext)

    def test_create_finished_starts_with_type_byte(self):
        self.hs.create_client_hello()
        self.hs.create_server_hello()
        self.hs.compute_master_secret(b'\x00' * 48)
        msg = self.hs.create_finished()
        self.assertEqual(msg[0], HANDSHAKE_FINISHED)

    def test_null_cipher_suite_offered(self):
        """Intentional weakness: null cipher suite is in the default list."""
        self.assertIn(SSL_NULL_WITH_NULL_NULL, self.hs.cipher_suites)

    def test_deflate_compression_offered(self):
        """Intentional weakness: CRIME-vulnerable compression is offered."""
        self.assertIn(COMPRESSION_DEFLATE, self.hs.compression_methods)

    def test_rc4_cipher_offered(self):
        """Intentional weakness: broken RC4 cipher suite is offered."""
        self.assertIn(SSL_RSA_WITH_RC4_128_MD5, self.hs.cipher_suites)


# ---------------------------------------------------------------------------
# BrokenSSLConnection end-to-end tests
# ---------------------------------------------------------------------------

class TestBrokenSSLConnection(unittest.TestCase):

    def _make_connection(self) -> BrokenSSLConnection:
        conn = BrokenSSLConnection()
        conn.do_handshake()
        return conn

    def test_handshake_returns_expected_keys(self):
        conn = BrokenSSLConnection()
        result = conn.do_handshake()
        for key in ('client_hello', 'server_hello', 'master_secret', 'finished'):
            self.assertIn(key, result)

    def test_master_secret_is_48_bytes(self):
        conn = BrokenSSLConnection()
        result = conn.do_handshake()
        self.assertEqual(len(result['master_secret']), 48)

    def test_send_returns_bytes(self):
        conn = self._make_connection()
        raw = conn.send(b'hello')
        self.assertIsInstance(raw, bytes)

    def test_send_produces_ssl_record(self):
        conn = self._make_connection()
        raw = conn.send(b'test data')
        self.assertEqual(raw[0], CONTENT_TYPE_APPLICATION_DATA)

    def test_send_receive_roundtrip(self):
        conn = self._make_connection()
        message = b'roundtrip test'
        raw = conn.send(message)
        # Use a second connection with the same keys to receive
        receiver = BrokenSSLConnection()
        receiver.handshake_complete = True
        receiver.handshake._session_key = conn._session_key
        receiver.handshake._mac_key = conn._mac_key
        receiver._session_key = conn._session_key
        receiver._mac_key = conn._mac_key
        recovered = receiver.receive(raw)
        self.assertEqual(recovered, message)

    def test_send_without_handshake_raises(self):
        conn = BrokenSSLConnection()
        with self.assertRaises(RuntimeError):
            conn.send(b'oops')

    def test_receive_tampered_data_raises(self):
        conn = self._make_connection()
        raw = conn.send(b'important data')
        # Flip a bit in the payload to corrupt the MAC
        raw_list = bytearray(raw)
        raw_list[-1] ^= 0xFF
        with self.assertRaises((ValueError, Exception)):
            conn.receive(bytes(raw_list))

    def test_vulnerability_hardcoded_fallback_key(self):
        """Verify the hardcoded fallback key weakness is present."""
        conn = BrokenSSLConnection()
        self.assertEqual(conn._session_key, b'hardcoded_key_12')

    def test_vulnerability_sequence_number_not_in_mac(self):
        """
        Demonstrate replay-attack weakness: two identical plaintexts produce
        identical ciphertexts (no sequence number mixed into the MAC).
        """
        conn = self._make_connection()
        raw1 = conn.send(b'replay me')
        # Reset sequence counter without changing anything else
        conn._sequence_number = 0
        raw2 = conn.send(b'replay me')
        # The ciphertexts should be identical (RC4 with same key = same stream)
        self.assertEqual(raw1, raw2)


if __name__ == '__main__':
    unittest.main()
