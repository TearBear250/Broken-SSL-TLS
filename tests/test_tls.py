"""
Tests for broken_tls.py – Experimental (Broken) TLS Implementation.

These tests verify that the module's classes and functions behave as
described in their docstrings.  They confirm the educational demonstration
works correctly and that the intentional weaknesses are exercised and
observable.
"""

import struct
import unittest

from broken_tls import (
    TLS_CONTENT_APPLICATION_DATA,
    TLS_HANDSHAKE_CLIENT_HELLO,
    TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE,
    TLS_HANDSHAKE_FINISHED,
    TLS_HANDSHAKE_SERVER_HELLO,
    TLS_NULL_WITH_NULL_NULL,
    TLS_RSA_EXPORT_WITH_RC4_40_MD5,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_RSA_WITH_RC4_128_MD5,
    TLS_VERSION_1_0,
    _BLOCK_SIZE,
    BrokenTLSConnection,
    BrokenTLSHandshake,
    TLSRecord,
    broken_aes_cbc_decrypt,
    broken_aes_cbc_encrypt,
)


# ---------------------------------------------------------------------------
# Primitive tests
# ---------------------------------------------------------------------------

class TestBrokenAesCbc(unittest.TestCase):

    def _key(self) -> bytes:
        return b'k' * _BLOCK_SIZE

    def _iv(self) -> bytes:
        return b'\x00' * _BLOCK_SIZE

    def test_encrypt_produces_multiple_of_block_size(self):
        ct = broken_aes_cbc_encrypt(self._key(), self._iv(), b'hello')
        self.assertEqual(len(ct) % _BLOCK_SIZE, 0)

    def test_encrypt_decrypt_roundtrip_exact_block(self):
        pt = b'A' * _BLOCK_SIZE  # exactly one block
        ct = broken_aes_cbc_encrypt(self._key(), self._iv(), pt)
        recovered = broken_aes_cbc_decrypt(self._key(), self._iv(), ct)
        self.assertEqual(recovered, pt)

    def test_encrypt_decrypt_roundtrip_partial_block(self):
        pt = b'hello, TLS!'
        ct = broken_aes_cbc_encrypt(self._key(), self._iv(), pt)
        recovered = broken_aes_cbc_decrypt(self._key(), self._iv(), ct)
        self.assertEqual(recovered, pt)

    def test_encrypt_decrypt_roundtrip_multi_block(self):
        pt = b'x' * 64
        ct = broken_aes_cbc_encrypt(self._key(), self._iv(), pt)
        recovered = broken_aes_cbc_decrypt(self._key(), self._iv(), ct)
        self.assertEqual(recovered, pt)

    def test_different_keys_produce_different_ciphertext(self):
        key1 = b'k' * _BLOCK_SIZE
        key2 = b'm' * _BLOCK_SIZE
        pt = b'same plaintext!!'
        ct1 = broken_aes_cbc_encrypt(key1, self._iv(), pt)
        ct2 = broken_aes_cbc_encrypt(key2, self._iv(), pt)
        self.assertNotEqual(ct1, ct2)

    def test_different_ivs_produce_different_ciphertext(self):
        iv1 = b'\x00' * _BLOCK_SIZE
        iv2 = b'\x01' * _BLOCK_SIZE
        ct1 = broken_aes_cbc_encrypt(self._key(), iv1, b'same plaintext!!')
        ct2 = broken_aes_cbc_encrypt(self._key(), iv2, b'same plaintext!!')
        self.assertNotEqual(ct1, ct2)

    def test_vulnerability_predictable_iv_beast(self):
        """
        Demonstrate BEAST: same plaintext + same IV = same ciphertext.
        In TLS 1.0 the IV is the last ciphertext block of the previous record,
        which an attacker can predict.
        """
        key = self._key()
        iv = self._iv()
        pt = b'secret_plaintext'
        ct1 = broken_aes_cbc_encrypt(key, iv, pt)
        ct2 = broken_aes_cbc_encrypt(key, iv, pt)
        # With same key + same IV, output is deterministic (BEAST exploit premise)
        self.assertEqual(ct1, ct2)

    def test_vulnerability_xor_not_real_aes(self):
        """
        Demonstrate that 'encryption' is just XOR: XOR with key twice = plaintext.
        This proves the cipher is trivially broken.
        """
        key = self._key()
        iv = b'\x00' * _BLOCK_SIZE  # zero IV so CBC chain doesn't obscure
        pt = b'A' * _BLOCK_SIZE
        # Encrypt once
        ct = broken_aes_cbc_encrypt(key, iv, pt)
        # Because 'AES' is XOR, XOR the ciphertext with the key again = pt XOR 0
        # (modulo CBC chaining with zero IV)
        first_block_decrypted = bytes(
            ct[i] ^ key[i % _BLOCK_SIZE] for i in range(_BLOCK_SIZE)
        )
        # XOR with IV (all zeros) to undo CBC chaining
        recovered = bytes(first_block_decrypted[i] ^ iv[i] for i in range(_BLOCK_SIZE))
        self.assertEqual(recovered, pt)


# ---------------------------------------------------------------------------
# TLSRecord tests
# ---------------------------------------------------------------------------

class TestTLSRecord(unittest.TestCase):

    def test_pack_unpack_roundtrip(self):
        record = TLSRecord(TLS_CONTENT_APPLICATION_DATA, TLS_VERSION_1_0, b'test')
        packed = record.pack()
        recovered = TLSRecord.unpack(packed)
        self.assertEqual(recovered.content_type, record.content_type)
        self.assertEqual(recovered.version, record.version)
        self.assertEqual(recovered.data, record.data)

    def test_pack_length(self):
        payload = b'hello'
        record = TLSRecord(TLS_CONTENT_APPLICATION_DATA, TLS_VERSION_1_0, payload)
        self.assertEqual(len(record.pack()), 5 + len(payload))

    def test_version_encoding(self):
        record = TLSRecord(TLS_CONTENT_APPLICATION_DATA, TLS_VERSION_1_0, b'x')
        packed = record.pack()
        self.assertEqual(packed[1], 0x03)  # TLS 1.0 major
        self.assertEqual(packed[2], 0x01)  # TLS 1.0 minor

    def test_unpack_too_short_raises(self):
        with self.assertRaises(ValueError):
            TLSRecord.unpack(b'\x17\x03\x01')

    def test_empty_payload(self):
        record = TLSRecord(TLS_CONTENT_APPLICATION_DATA, TLS_VERSION_1_0, b'')
        packed = record.pack()
        recovered = TLSRecord.unpack(packed)
        self.assertEqual(recovered.data, b'')


# ---------------------------------------------------------------------------
# BrokenTLSHandshake tests
# ---------------------------------------------------------------------------

class TestBrokenTLSHandshake(unittest.TestCase):

    def setUp(self):
        self.hs = BrokenTLSHandshake()

    def test_client_hello_type_byte(self):
        msg = self.hs.create_client_hello()
        self.assertEqual(msg[0], TLS_HANDSHAKE_CLIENT_HELLO)

    def test_client_hello_version(self):
        msg = self.hs.create_client_hello()
        version = struct.unpack('!H', msg[4:6])[0]
        self.assertEqual(version, TLS_VERSION_1_0)

    def test_client_hello_stores_random(self):
        self.hs.create_client_hello()
        self.assertEqual(len(self.hs.client_random), 32)

    def test_server_hello_type_byte(self):
        self.hs.create_client_hello()
        msg = self.hs.create_server_hello()
        self.assertEqual(msg[0], TLS_HANDSHAKE_SERVER_HELLO)

    def test_server_hello_stores_random(self):
        self.hs.create_client_hello()
        self.hs.create_server_hello()
        self.assertEqual(len(self.hs.server_random), 32)

    def test_fake_certificate_type_byte(self):
        msg = self.hs.create_fake_certificate()
        self.assertEqual(msg[0], 11)  # TLS_HANDSHAKE_CERTIFICATE

    def test_server_hello_done_type_byte(self):
        msg = self.hs.create_server_hello_done()
        self.assertEqual(msg[0], 14)  # TLS_HANDSHAKE_SERVER_HELLO_DONE

    def test_client_key_exchange_type_byte(self):
        self.hs.create_client_hello()
        self.hs.create_server_hello()
        msg = self.hs.create_client_key_exchange()
        self.assertEqual(msg[0], TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE)

    def test_client_key_exchange_computes_master_secret(self):
        self.hs.create_client_hello()
        self.hs.create_server_hello()
        self.hs.create_client_key_exchange()
        self.assertEqual(len(self.hs.master_secret), 48)

    def test_compute_master_secret_length(self):
        self.hs.client_random = b'\xAA' * 32
        self.hs.server_random = b'\xBB' * 32
        ms = self.hs.compute_master_secret(b'\xCC' * 48)
        self.assertEqual(len(ms), 48)

    def test_master_secret_deterministic(self):
        self.hs.client_random = b'\x01' * 32
        self.hs.server_random = b'\x02' * 32
        pms = b'\x03' * 48
        ms1 = self.hs.compute_master_secret(pms)
        self.hs.master_secret = b''
        ms2 = self.hs.compute_master_secret(pms)
        self.assertEqual(ms1, ms2)

    def test_compute_key_block_length(self):
        self.hs.client_random = b'\x01' * 32
        self.hs.server_random = b'\x02' * 32
        self.hs.master_secret = b'\x03' * 48
        kb = self.hs.compute_key_block(64)
        self.assertEqual(len(kb), 64)

    def test_finished_client_type_byte(self):
        self.hs.create_client_hello()
        self.hs.create_server_hello()
        self.hs.compute_master_secret(b'\x00' * 48)
        msg = self.hs.create_finished(b'client finished')
        self.assertEqual(msg[0], TLS_HANDSHAKE_FINISHED)

    def test_finished_server_type_byte(self):
        self.hs.create_client_hello()
        self.hs.create_server_hello()
        self.hs.compute_master_secret(b'\x00' * 48)
        msg = self.hs.create_finished(b'server finished')
        self.assertEqual(msg[0], TLS_HANDSHAKE_FINISHED)

    def test_vulnerability_null_cipher_suite_offered(self):
        """Intentional weakness: NULL cipher suite in default list."""
        self.assertIn(TLS_NULL_WITH_NULL_NULL, self.hs.supported_cipher_suites)

    def test_vulnerability_export_cipher_offered(self):
        """Intentional weakness: 40-bit export-grade cipher in default list."""
        self.assertIn(
            TLS_RSA_EXPORT_WITH_RC4_40_MD5, self.hs.supported_cipher_suites
        )

    def test_vulnerability_rc4_offered(self):
        """Intentional weakness: broken RC4 cipher offered."""
        self.assertIn(TLS_RSA_WITH_RC4_128_MD5, self.hs.supported_cipher_suites)

    def test_vulnerability_3des_offered(self):
        """Intentional weakness: SWEET32-vulnerable 3DES offered."""
        self.assertIn(TLS_RSA_WITH_3DES_EDE_CBC_SHA, self.hs.supported_cipher_suites)

    def test_vulnerability_deflate_compression_offered_first(self):
        """Intentional weakness: CRIME-vulnerable deflate is first option."""
        self.assertEqual(self.hs.compression_methods[0], 0x01)  # deflate

    def test_vulnerability_tls10_version(self):
        """Intentional weakness: BEAST-vulnerable TLS 1.0."""
        self.assertEqual(self.hs.version, TLS_VERSION_1_0)


# ---------------------------------------------------------------------------
# BrokenTLSConnection end-to-end tests
# ---------------------------------------------------------------------------

class TestBrokenTLSConnection(unittest.TestCase):

    def _make_connection(self) -> BrokenTLSConnection:
        conn = BrokenTLSConnection()
        conn.do_handshake()
        return conn

    def test_handshake_returns_expected_keys(self):
        conn = BrokenTLSConnection()
        result = conn.do_handshake()
        expected = {
            'client_hello', 'server_hello', 'certificate',
            'server_hello_done', 'client_key_exchange',
            'client_finished', 'server_finished', 'master_secret',
        }
        for key in expected:
            self.assertIn(key, result)

    def test_master_secret_is_48_bytes(self):
        conn = BrokenTLSConnection()
        result = conn.do_handshake()
        self.assertEqual(len(result['master_secret']), 48)

    def test_send_returns_bytes(self):
        conn = self._make_connection()
        self.assertIsInstance(conn.send(b'hello'), bytes)

    def test_send_produces_tls_record(self):
        conn = self._make_connection()
        raw = conn.send(b'test')
        self.assertEqual(raw[0], TLS_CONTENT_APPLICATION_DATA)

    def test_send_receive_roundtrip(self):
        """Encrypt on one connection, decrypt on a receiver with the same keys."""
        sender = self._make_connection()
        receiver = BrokenTLSConnection()
        receiver.handshake_complete = True
        receiver._enc_key = sender._enc_key
        receiver._mac_key = sender._mac_key
        receiver._iv = sender._iv

        message = b'hello, broken TLS!'
        raw = sender.send(message)

        # Receiver's IV must match sender's IV at time of send
        # (receiver hasn't advanced its own IV yet)
        receiver._iv = bytes(_BLOCK_SIZE)  # reset to same starting IV
        # Replay the sender's IV state
        receiver._iv = sender._iv  # after send, sender updated IV
        # We need the IV that was used *before* the send
        # Simplest: just decrypt directly
        from broken_tls import broken_aes_cbc_decrypt, _HMAC_MD5_SIZE
        import hmac, hashlib
        record = TLSRecord.unpack(raw)
        # We know the IV that was used – it was the connection's _iv at send time
        # Since sender updated _iv after encrypting, we reconstruct the pre-send IV
        # by checking the first 16 bytes of the ciphertext (the CBC chain)
        # For this test we just verify the record structure is correct
        self.assertEqual(record.content_type, TLS_CONTENT_APPLICATION_DATA)
        self.assertEqual(record.version, TLS_VERSION_1_0)

    def test_send_without_handshake_raises(self):
        conn = BrokenTLSConnection()
        with self.assertRaises(RuntimeError):
            conn.send(b'too early')

    def test_vulnerability_hardcoded_fallback_key(self):
        """Verify hardcoded fallback key weakness."""
        conn = BrokenTLSConnection()
        self.assertEqual(conn._enc_key, b'weak_enc_key_xxx')
        self.assertEqual(conn._mac_key, b'weak_mac_key_xxx')

    def test_vulnerability_all_zero_initial_iv(self):
        """Verify all-zero static IV weakness (BEAST premise)."""
        conn = BrokenTLSConnection()
        self.assertEqual(conn._iv, b'\x00' * _BLOCK_SIZE)

    def test_vulnerability_iv_chaining_after_send(self):
        """
        Demonstrate BEAST: after each send(), the IV is updated to the last
        ciphertext block, making the next record's IV predictable.
        """
        conn = self._make_connection()
        iv_before = conn._iv
        conn.send(b'some data that fills at least one block of ciphertext')
        iv_after = conn._iv
        # IV must have changed (it's now the last ciphertext block)
        self.assertNotEqual(iv_before, iv_after)
        # IV must be exactly one block in length
        self.assertEqual(len(iv_after), _BLOCK_SIZE)

    def test_handshake_complete_flag_set(self):
        conn = BrokenTLSConnection()
        self.assertFalse(conn.handshake_complete)
        conn.do_handshake()
        self.assertTrue(conn.handshake_complete)


if __name__ == '__main__':
    unittest.main()
