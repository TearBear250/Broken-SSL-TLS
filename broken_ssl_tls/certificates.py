"""
Broken Certificate Validation
==============================

This module demonstrates the ways certificate validation can be skipped or
weakened, enabling man-in-the-middle (MITM) attacks.

WARNING: These validators are intentionally insecure.  They should never be
used to make real trust decisions.
"""

import hashlib
import struct
import time
from typing import Optional


class CertificateInfo:
    """
    A simplified certificate data structure for demonstration purposes.

    Fields match a subset of X.509 v3 certificate fields (RFC 5280).
    """

    def __init__(
        self,
        subject: str,
        issuer: str,
        not_before: float,
        not_after: float,
        public_key_bits: int = 2048,
        signature_algorithm: str = "sha256WithRSAEncryption",
        san: Optional[list] = None,
        self_signed: bool = False,
    ):
        self.subject = subject
        self.issuer = issuer
        self.not_before = not_before
        self.not_after = not_after
        self.public_key_bits = public_key_bits
        self.signature_algorithm = signature_algorithm
        self.san = san or []  # Subject Alternative Names
        self.self_signed = self_signed or (subject == issuer)

    @property
    def is_expired(self) -> bool:
        return time.time() > self.not_after

    @property
    def is_not_yet_valid(self) -> bool:
        return time.time() < self.not_before

    def __repr__(self):
        return (
            f"CertificateInfo(subject={self.subject!r}, issuer={self.issuer!r}, "
            f"self_signed={self.self_signed})"
        )


class ValidationResult:
    """Result of a certificate validation check."""

    def __init__(self):
        self.valid = True
        self.errors: list = []
        self.warnings: list = []

    def add_error(self, message: str):
        self.valid = False
        self.errors.append(message)

    def add_warning(self, message: str):
        self.warnings.append(message)

    def __bool__(self):
        return self.valid

    def __repr__(self):
        return (
            f"ValidationResult(valid={self.valid}, "
            f"errors={self.errors}, warnings={self.warnings})"
        )


class BrokenCertValidator:
    """
    A certificate validator that can be configured to skip critical checks.

    Each flag corresponds to a real-world vulnerability class seen in broken
    SSL/TLS stacks.

    Example usage::

        validator = BrokenCertValidator()
        cert = CertificateInfo(
            subject="example.com",
            issuer="Self-Signed CA",
            not_before=0,
            not_after=0,   # expired!
            self_signed=True,
        )
        result = validator.validate(cert, hostname="evil.com")
        print(result)  # valid=True because all checks are disabled
    """

    def __init__(self):
        # VULNERABILITY (CWE-295): Skip all certificate verification
        self.verify_chain = False

        # VULNERABILITY (CWE-297): Skip hostname matching
        self.verify_hostname = False

        # VULNERABILITY: Accept expired certificates
        self.verify_expiry = False

        # VULNERABILITY: Accept self-signed certificates
        self.reject_self_signed = False

        # VULNERABILITY: Accept MD5 and SHA-1 signed certificates
        self.reject_weak_signature = False

        # VULNERABILITY: Accept certificates with short RSA keys (< 2048 bits)
        self.minimum_key_bits = 0

    # ------------------------------------------------------------------
    # Individual check methods (each can be bypassed by the flags above)
    # ------------------------------------------------------------------

    def check_hostname(self, cert: CertificateInfo, hostname: str) -> ValidationResult:
        """
        VULNERABILITY (CWE-297): When verify_hostname is False this method
        always returns valid, even when the certificate's subject/SAN has
        nothing to do with the requested hostname.

        Real-world examples: early Android SSL libraries, OpenSSL before
        1.0.2 lacked built-in hostname verification (CVE-2010-4180 class).
        """
        result = ValidationResult()
        if not self.verify_hostname:
            result.add_warning(
                "Hostname verification is DISABLED – certificate accepted for any hostname."
            )
            return result

        names = list(cert.san)
        # Extract CN from subject "CN=hostname"
        for part in cert.subject.split(","):
            part = part.strip()
            if part.upper().startswith("CN="):
                names.append(part[3:])

        for name in names:
            if self._match_hostname(hostname, name):
                return result

        result.add_error(
            f"Hostname mismatch: certificate is for {names!r}, not {hostname!r}."
        )
        return result

    def check_expiry(self, cert: CertificateInfo) -> ValidationResult:
        """
        VULNERABILITY: When verify_expiry is False this method accepts
        certificates regardless of their validity period, including certs
        that expired years ago.

        Expired certificates may have been re-issued after compromise, so
        accepting them undermines the entire revocation model.
        """
        result = ValidationResult()
        if not self.verify_expiry:
            result.add_warning(
                "Expiry check is DISABLED – expired certificates are accepted."
            )
            return result

        now = time.time()
        if cert.is_expired:
            result.add_error("Certificate has expired.")
        if cert.is_not_yet_valid:
            result.add_error("Certificate is not yet valid.")
        return result

    def check_chain(self, cert: CertificateInfo) -> ValidationResult:
        """
        VULNERABILITY (CWE-295): When verify_chain is False no chain of
        trust is established.  An attacker can present any self-signed cert
        and it will be accepted.

        This is the most severe validation flaw and enables trivial MITM
        attacks on any TLS connection.
        """
        result = ValidationResult()
        if not self.verify_chain:
            result.add_warning(
                "Chain verification is DISABLED – any certificate is trusted."
            )
            return result

        if cert.self_signed and self.reject_self_signed:
            result.add_error("Certificate is self-signed and not in the trust store.")
        return result

    def check_signature_algorithm(self, cert: CertificateInfo) -> ValidationResult:
        """
        VULNERABILITY: Accept MD5 or SHA-1 signed certificates.

        MD5 collisions allow forging certificates (CVE-2004-2761, rogue CA
        demonstrated at CCC 2008).  SHA-1 collision shown by Google/CWI in
        2017 (SHAttered).  Both are banned by modern browsers.
        """
        result = ValidationResult()
        weak_algorithms = {"md5WithRSAEncryption", "sha1WithRSAEncryption"}
        if cert.signature_algorithm.lower() in {a.lower() for a in weak_algorithms}:
            if self.reject_weak_signature:
                result.add_error(
                    f"Weak signature algorithm: {cert.signature_algorithm!r}. "
                    "MD5 and SHA-1 are cryptographically broken."
                )
            else:
                result.add_warning(
                    f"Weak signature algorithm accepted: {cert.signature_algorithm!r}."
                )
        return result

    def check_key_strength(self, cert: CertificateInfo) -> ValidationResult:
        """
        VULNERABILITY: Accept certificates with short RSA keys.

        RSA-512 was factored in 1999; RSA-768 in 2009; RSA-1024 is considered
        at-risk.  NIST recommends at least 2048 bits.  Short keys combined
        with EXPORT cipher suites are the basis of the FREAK attack.
        """
        result = ValidationResult()
        if cert.public_key_bits < self.minimum_key_bits:
            result.add_error(
                f"Key too short: {cert.public_key_bits} bits "
                f"(minimum is {self.minimum_key_bits} bits)."
            )
        elif cert.public_key_bits < 2048:
            result.add_warning(
                f"Weak key: {cert.public_key_bits}-bit RSA key accepted "
                "(NIST recommends ≥ 2048 bits)."
            )
        return result

    def validate(
        self, cert: CertificateInfo, hostname: Optional[str] = None
    ) -> ValidationResult:
        """
        Run all configured validation checks and return an aggregated result.
        """
        result = ValidationResult()

        for sub_result in [
            self.check_chain(cert),
            self.check_expiry(cert),
            self.check_signature_algorithm(cert),
            self.check_key_strength(cert),
        ]:
            result.errors.extend(sub_result.errors)
            result.warnings.extend(sub_result.warnings)
            if not sub_result.valid:
                result.valid = False

        if hostname is not None:
            hn_result = self.check_hostname(cert, hostname)
            result.errors.extend(hn_result.errors)
            result.warnings.extend(hn_result.warnings)
            if not hn_result.valid:
                result.valid = False

        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _match_hostname(hostname: str, pattern: str) -> bool:
        """Simplified wildcard hostname matching (RFC 6125 §6.4)."""
        hostname = hostname.lower()
        pattern = pattern.lower()
        if pattern.startswith("*."):
            suffix = pattern[1:]  # e.g. ".example.com"
            return (
                hostname.endswith(suffix)
                and hostname.count(".") == pattern.count(".")
            )
        return hostname == pattern
