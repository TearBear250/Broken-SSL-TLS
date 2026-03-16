"""
Tests for the Broken SSL/TLS educational library.

Each test verifies that the intentional vulnerabilities behave as described
so that students can run them and see concrete evidence of the flaws.
"""

import hashlib
import struct
import time
import unittest

from broken_ssl_tls import (
    BrokenCertValidator,
    BrokenTLSContext,
    BrokenTLSRecord,
    NullCipher,
    RC4Cipher,
    WeakExportCipher,
)
from broken_ssl_tls.ciphers import DESCipher
from broken_ssl_tls.certificates import CertificateInfo
from broken_ssl_tls.protocol import CipherSuiteID, ProtocolVersion
from broken_ssl_tls.record import BrokenMAC


# ---------------------------------------------------------------------------
# NullCipher
# ---------------------------------------------------------------------------


class TestNullCipher(unittest.TestCase):
    def setUp(self):
        self.cipher = NullCipher()

    def test_encrypt_returns_plaintext_unchanged(self):
        msg = b"Hello, World!"
        self.assertEqual(self.cipher.encrypt(msg), msg)

    def test_decrypt_returns_ciphertext_unchanged(self):
        msg = b"Secret data"
        self.assertEqual(self.cipher.decrypt(msg), msg)

    def test_encrypt_empty(self):
        self.assertEqual(self.cipher.encrypt(b""), b"")

    def test_roundtrip(self):
        msg = b"No encryption applied"
        self.assertEqual(self.cipher.decrypt(self.cipher.encrypt(msg)), msg)

    def test_key_size_is_zero(self):
        self.assertEqual(self.cipher.key_size, 0)


# ---------------------------------------------------------------------------
# RC4Cipher
# ---------------------------------------------------------------------------


class TestRC4Cipher(unittest.TestCase):
    def setUp(self):
        self.cipher = RC4Cipher()
        self.key = b"secretkey1234567"  # 16 bytes

    def test_encrypt_differs_from_plaintext(self):
        plaintext = b"Attack at dawn"
        ciphertext = self.cipher.encrypt(plaintext, self.key)
        self.assertNotEqual(ciphertext, plaintext)

    def test_roundtrip(self):
        plaintext = b"The quick brown fox jumps over the lazy dog"
        ciphertext = self.cipher.encrypt(plaintext, self.key)
        recovered = self.cipher.decrypt(ciphertext, self.key)
        self.assertEqual(recovered, plaintext)

    def test_different_keys_produce_different_ciphertext(self):
        plaintext = b"Same plaintext"
        ct1 = self.cipher.encrypt(plaintext, b"key0000000000001")
        ct2 = self.cipher.encrypt(plaintext, b"key0000000000002")
        self.assertNotEqual(ct1, ct2)

    def test_encrypt_empty(self):
        self.assertEqual(self.cipher.encrypt(b"", self.key), b"")

    def test_length_preserved(self):
        plaintext = b"exactly sixteen!"
        ciphertext = self.cipher.encrypt(plaintext, self.key)
        self.assertEqual(len(ciphertext), len(plaintext))

    def test_known_vulnerability_same_key_reuse(self):
        """RC4 reusing the same key is trivially breakable: C1 XOR C2 = P1 XOR P2."""
        p1 = b"Hello secret msg"
        p2 = b"Admin password!!"
        c1 = self.cipher.encrypt(p1, self.key)
        c2 = self.cipher.encrypt(p2, self.key)
        xor_ct = bytes(a ^ b for a, b in zip(c1, c2))
        xor_pt = bytes(a ^ b for a, b in zip(p1, p2))
        self.assertEqual(xor_ct, xor_pt)


# ---------------------------------------------------------------------------
# WeakExportCipher
# ---------------------------------------------------------------------------


class TestWeakExportCipher(unittest.TestCase):
    def setUp(self):
        self.cipher = WeakExportCipher()
        self.key = b"\x01\x02\x03\x04\x05"  # 40-bit key

    def test_roundtrip(self):
        plaintext = b"FREAK vulnerability demo"
        ciphertext = self.cipher.encrypt(plaintext, self.key)
        recovered = self.cipher.decrypt(ciphertext, self.key)
        self.assertEqual(recovered, plaintext)

    def test_wrong_key_length_raises(self):
        with self.assertRaises(ValueError):
            self.cipher.encrypt(b"data", b"\x01\x02\x03")  # only 3 bytes

    def test_key_size_attribute(self):
        self.assertEqual(self.cipher.key_size, 5)

    def test_small_keyspace(self):
        """40-bit = 2^40 ≈ 1 trillion keys – verify the key is only 5 bytes."""
        self.assertEqual(len(self.key) * 8, 40)


# ---------------------------------------------------------------------------
# DESCipher
# ---------------------------------------------------------------------------


class TestDESCipher(unittest.TestCase):
    def setUp(self):
        self.cipher = DESCipher()
        self.key = b"\x01\x02\x03\x04\x05\x06\x07"  # 7 bytes = 56 bits

    def test_roundtrip(self):
        plaintext = b"Short message"
        iv = b"\x00" * 8
        ciphertext = self.cipher.encrypt(plaintext, self.key, iv)
        recovered = self.cipher.decrypt(ciphertext, self.key, iv)
        self.assertEqual(recovered, plaintext)

    def test_ciphertext_differs_from_plaintext(self):
        plaintext = b"A" * 8
        iv = b"\x00" * 8
        ciphertext = self.cipher.encrypt(plaintext, self.key, iv)
        self.assertNotEqual(ciphertext, plaintext)

    def test_wrong_key_length_raises(self):
        with self.assertRaises(ValueError):
            self.cipher.encrypt(b"data", b"\x01\x02\x03")

    def test_key_size_is_56_bit(self):
        self.assertEqual(self.cipher.key_size * 8, 56)

    def test_zero_iv_vulnerability(self):
        """Verify that default IV is all-zeros (known vulnerability)."""
        plaintext = b"Sensitive data!!"
        ct_default = self.cipher.encrypt(plaintext, self.key, iv=None)
        ct_explicit_zero = self.cipher.encrypt(plaintext, self.key, iv=b"\x00" * 8)
        self.assertEqual(ct_default, ct_explicit_zero)


# ---------------------------------------------------------------------------
# BrokenCertValidator
# ---------------------------------------------------------------------------


class TestBrokenCertValidator(unittest.TestCase):
    def _expired_cert(self):
        return CertificateInfo(
            subject="CN=example.com",
            issuer="CN=Root CA",
            not_before=0.0,
            not_after=1.0,  # expired in 1970
        )

    def _self_signed_cert(self):
        return CertificateInfo(
            subject="CN=self.example.com",
            issuer="CN=self.example.com",
            not_before=time.time() - 3600,
            not_after=time.time() + 3600,
            self_signed=True,
        )

    def _md5_cert(self):
        return CertificateInfo(
            subject="CN=legacy.example.com",
            issuer="CN=Old CA",
            not_before=time.time() - 3600,
            not_after=time.time() + 3600,
            signature_algorithm="md5WithRSAEncryption",
        )

    def _weak_key_cert(self):
        return CertificateInfo(
            subject="CN=weak.example.com",
            issuer="CN=CA",
            not_before=time.time() - 3600,
            not_after=time.time() + 3600,
            public_key_bits=512,
        )

    def test_default_validator_accepts_expired_cert(self):
        """VULNERABILITY: expiry check disabled by default."""
        validator = BrokenCertValidator()
        result = validator.validate(self._expired_cert())
        self.assertTrue(result.valid)

    def test_enabled_expiry_check_rejects_expired_cert(self):
        validator = BrokenCertValidator()
        validator.verify_expiry = True
        result = validator.validate(self._expired_cert())
        self.assertFalse(result.valid)
        self.assertTrue(any("expired" in e.lower() for e in result.errors))

    def test_default_validator_accepts_any_hostname(self):
        """VULNERABILITY: hostname check disabled by default."""
        validator = BrokenCertValidator()
        cert = CertificateInfo(
            subject="CN=example.com",
            issuer="CN=CA",
            not_before=time.time() - 3600,
            not_after=time.time() + 3600,
        )
        result = validator.validate(cert, hostname="evil.com")
        self.assertTrue(result.valid)

    def test_enabled_hostname_check_rejects_mismatch(self):
        validator = BrokenCertValidator()
        validator.verify_hostname = True
        cert = CertificateInfo(
            subject="CN=example.com",
            issuer="CN=CA",
            not_before=time.time() - 3600,
            not_after=time.time() + 3600,
        )
        result = validator.validate(cert, hostname="evil.com")
        self.assertFalse(result.valid)

    def test_hostname_check_wildcard_match(self):
        validator = BrokenCertValidator()
        validator.verify_hostname = True
        cert = CertificateInfo(
            subject="CN=*.example.com",
            issuer="CN=CA",
            not_before=time.time() - 3600,
            not_after=time.time() + 3600,
            san=["*.example.com"],
        )
        result = validator.validate(cert, hostname="sub.example.com")
        self.assertTrue(result.valid)

    def test_default_validator_accepts_self_signed(self):
        """VULNERABILITY: chain verification disabled by default."""
        validator = BrokenCertValidator()
        result = validator.validate(self._self_signed_cert())
        self.assertTrue(result.valid)

    def test_enabled_chain_check_rejects_self_signed(self):
        validator = BrokenCertValidator()
        validator.verify_chain = True
        validator.reject_self_signed = True
        result = validator.validate(self._self_signed_cert())
        self.assertFalse(result.valid)

    def test_default_validator_accepts_md5_signature(self):
        """VULNERABILITY: weak signature algorithm accepted by default."""
        validator = BrokenCertValidator()
        result = validator.validate(self._md5_cert())
        self.assertTrue(result.valid)
        self.assertTrue(any("weak" in w.lower() for w in result.warnings))

    def test_enabled_sig_check_rejects_md5(self):
        validator = BrokenCertValidator()
        validator.reject_weak_signature = True
        result = validator.validate(self._md5_cert())
        self.assertFalse(result.valid)

    def test_default_validator_accepts_512bit_key(self):
        """VULNERABILITY: minimum_key_bits is 0 by default."""
        validator = BrokenCertValidator()
        result = validator.validate(self._weak_key_cert())
        self.assertTrue(result.valid)

    def test_minimum_key_bits_enforcement(self):
        validator = BrokenCertValidator()
        validator.minimum_key_bits = 2048
        result = validator.validate(self._weak_key_cert())
        self.assertFalse(result.valid)
        self.assertTrue(any("512" in e for e in result.errors))


# ---------------------------------------------------------------------------
# BrokenTLSContext and BrokenTLSHandshake
# ---------------------------------------------------------------------------


class TestBrokenTLSContext(unittest.TestCase):
    def setUp(self):
        self.ctx = BrokenTLSContext()

    def test_default_verify_certificates_is_false(self):
        self.assertFalse(self.ctx.verify_certificates)

    def test_default_check_hostname_is_false(self):
        self.assertFalse(self.ctx.check_hostname)

    def test_default_minimum_version_is_ssl20(self):
        self.assertEqual(self.ctx.minimum_version, ProtocolVersion.SSL_2_0)

    def test_default_cipher_suites_include_null(self):
        self.assertIn(CipherSuiteID.TLS_NULL_WITH_NULL_NULL, self.ctx.cipher_suites)

    def test_vulnerability_report_is_non_empty(self):
        report = self.ctx.get_vulnerability_report()
        self.assertGreater(len(report), 0)

    def test_vulnerability_report_contains_cert_issue(self):
        report = self.ctx.get_vulnerability_report()
        titles = [r["title"] for r in report]
        self.assertTrue(any("certificate" in t.lower() for t in titles))

    def test_vulnerability_report_contains_cipher_issue(self):
        report = self.ctx.get_vulnerability_report()
        titles = [r["title"] for r in report]
        self.assertTrue(any("cipher" in t.lower() for t in titles))

    def test_create_handshake_returns_handshake_object(self):
        from broken_ssl_tls.protocol import BrokenTLSHandshake

        hs = self.ctx.create_handshake("example.com")
        self.assertIsInstance(hs, BrokenTLSHandshake)


class TestBrokenTLSHandshake(unittest.TestCase):
    def setUp(self):
        self.ctx = BrokenTLSContext()
        self.hs = self.ctx.create_handshake("example.com")

    def test_client_hello_returns_bytes(self):
        msg = self.hs.create_client_hello()
        self.assertIsInstance(msg, bytes)

    def test_client_hello_first_byte_is_client_hello_type(self):
        msg = self.hs.create_client_hello()
        self.assertEqual(msg[0], 1)  # HandshakeType.CLIENT_HELLO = 1

    def test_client_random_is_set_after_client_hello(self):
        self.hs.create_client_hello()
        self.assertIsNotNone(self.hs.client_random)
        self.assertEqual(len(self.hs.client_random), 32)

    def test_server_hello_returns_bytes(self):
        self.hs.create_client_hello()
        msg = self.hs.simulate_server_hello()
        self.assertIsInstance(msg, bytes)

    def test_server_hello_first_byte_is_server_hello_type(self):
        self.hs.create_client_hello()
        msg = self.hs.simulate_server_hello()
        self.assertEqual(msg[0], 2)  # HandshakeType.SERVER_HELLO = 2

    def test_negotiated_cipher_is_weakest(self):
        """Server selects the weakest (first) cipher from client's list."""
        self.hs.create_client_hello()
        self.hs.simulate_server_hello()
        self.assertEqual(
            self.hs.negotiated_cipher, CipherSuiteID.TLS_NULL_WITH_NULL_NULL
        )

    def test_negotiated_version_is_minimum(self):
        """Server downgrades to the minimum accepted version."""
        self.hs.create_client_hello()
        self.hs.simulate_server_hello()
        self.assertEqual(self.hs.negotiated_version, ProtocolVersion.SSL_2_0)

    def test_compute_master_secret_length_48(self):
        self.hs.create_client_hello()
        self.hs.simulate_server_hello()
        ms = self.hs.compute_master_secret(b"\x03\x03" + b"\xab" * 46)
        self.assertEqual(len(ms), 48)

    def test_compute_master_secret_raises_without_randoms(self):
        with self.assertRaises(RuntimeError):
            self.hs.compute_master_secret(b"\x00" * 48)

    def test_handshake_transcript_has_two_entries(self):
        self.hs.create_client_hello()
        self.hs.simulate_server_hello()
        transcript = self.hs.get_handshake_transcript()
        self.assertEqual(len(transcript), 2)
        labels = [t[0] for t in transcript]
        self.assertIn("CLIENT_HELLO", labels)
        self.assertIn("SERVER_HELLO", labels)


# ---------------------------------------------------------------------------
# BrokenTLSRecord
# ---------------------------------------------------------------------------


class TestBrokenTLSRecord(unittest.TestCase):
    def setUp(self):
        self.record = BrokenTLSRecord(version=(3, 1))

    def test_write_read_roundtrip_null_cipher(self):
        plaintext = b"Application data payload"
        raw = self.record.write_record(23, plaintext)  # 23 = APPLICATION_DATA
        parsed = self.record.read_record(raw)
        self.assertEqual(parsed["plaintext"], plaintext)

    def test_record_header_content_type(self):
        raw = self.record.write_record(23, b"test")
        self.assertEqual(raw[0], 23)

    def test_record_header_version(self):
        raw = self.record.write_record(23, b"test")
        self.assertEqual(raw[1], 3)
        self.assertEqual(raw[2], 1)

    def test_record_too_short_raises(self):
        with self.assertRaises(ValueError):
            self.record.read_record(b"\x17\x03")

    def test_sequence_number_increments(self):
        self.assertEqual(self.record._seq_num, 0)
        self.record.write_record(23, b"msg1")
        self.assertEqual(self.record._seq_num, 1)
        self.record.write_record(23, b"msg2")
        self.assertEqual(self.record._seq_num, 2)

    def test_padding_oracle_description_is_string(self):
        desc = self.record.demonstrate_padding_oracle()
        self.assertIsInstance(desc, str)
        self.assertIn("POODLE", desc)

    def test_write_read_roundtrip_rc4(self):
        key = b"sixteen_byte_key"
        rc4 = RC4Cipher()
        record = BrokenTLSRecord(version=(3, 1), cipher=rc4)
        plaintext = b"RC4 encrypted record"
        raw = record.write_record(23, plaintext, cipher_key=key)
        parsed = record.read_record(raw, cipher_key=key)
        self.assertEqual(parsed["plaintext"], plaintext)


# ---------------------------------------------------------------------------
# BrokenMAC
# ---------------------------------------------------------------------------


class TestBrokenMAC(unittest.TestCase):
    def test_null_mac_returns_empty(self):
        result = BrokenMAC.null_mac(b"key", b"data")
        self.assertEqual(result, b"")

    def test_ssl3_mac_returns_20_bytes(self):
        result = BrokenMAC.ssl3_mac(b"secret", b"hello")
        self.assertEqual(len(result), 20)  # SHA-1 output

    def test_ssl3_mac_different_data_different_mac(self):
        m1 = BrokenMAC.ssl3_mac(b"key", b"data1")
        m2 = BrokenMAC.ssl3_mac(b"key", b"data2")
        self.assertNotEqual(m1, m2)

    def test_truncated_hmac_length(self):
        result = BrokenMAC.truncated_hmac(b"key", b"data", length=10)
        self.assertEqual(len(result), 10)

    def test_truncated_hmac_shorter_than_full_hmac(self):
        import hmac as hmac_mod

        full = hmac_mod.new(b"key", b"data", hashlib.sha1).digest()
        truncated = BrokenMAC.truncated_hmac(b"key", b"data", length=10)
        self.assertEqual(truncated, full[:10])


# ---------------------------------------------------------------------------
# ProtocolVersion
# ---------------------------------------------------------------------------


class TestProtocolVersion(unittest.TestCase):
    def test_ssl20_bytes(self):
        self.assertEqual(ProtocolVersion.SSL_2_0.to_bytes(), b"\x00\x02")

    def test_ssl30_bytes(self):
        self.assertEqual(ProtocolVersion.SSL_3_0.to_bytes(), b"\x03\x00")

    def test_tls10_bytes(self):
        self.assertEqual(ProtocolVersion.TLS_1_0.to_bytes(), b"\x03\x01")

    def test_tls13_bytes(self):
        self.assertEqual(ProtocolVersion.TLS_1_3.to_bytes(), b"\x03\x04")


if __name__ == "__main__":
    unittest.main()
