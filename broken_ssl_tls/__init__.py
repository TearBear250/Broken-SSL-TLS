"""
Broken SSL/TLS – Educational Implementation
============================================

WARNING: This library is **intentionally insecure**.  It exists solely to
demonstrate well-known SSL/TLS vulnerabilities in a safe, offline setting.

DO NOT use this library for any real network communication or production
security.  It is provided for educational purposes only.

Quick start
-----------
>>> from broken_ssl_tls import BrokenTLSContext, ProtocolVersion
>>> ctx = BrokenTLSContext()
>>> print(ctx.get_vulnerability_report())
"""

from .protocol import BrokenTLSContext, BrokenTLSHandshake, ProtocolVersion, CipherSuiteID
from .ciphers import NullCipher, RC4Cipher, WeakExportCipher
from .certificates import BrokenCertValidator
from .record import BrokenTLSRecord

__version__ = "0.1.0"
__all__ = [
    "BrokenTLSContext",
    "BrokenTLSHandshake",
    "ProtocolVersion",
    "CipherSuiteID",
    "NullCipher",
    "RC4Cipher",
    "WeakExportCipher",
    "BrokenCertValidator",
    "BrokenTLSRecord",
]
