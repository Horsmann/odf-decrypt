"""
odf-decrypt: Decrypt password-protected OpenDocument Format (ODF) files.

This library supports decryption of ODF files created by both LibreOffice
and Apache OpenOffice, handling modern (AES-256-GCM, Argon2id) and legacy
(Blowfish-CFB, PBKDF2) encryption formats.
"""

from importlib.metadata import version

from odfdecrypt.cli import is_encrypted
from odfdecrypt.decryption.apache_odf_decryptor import AOODecryptor
from odfdecrypt.decryption.libre_office_odf_decryptor import LibreOfficeDecryptor
from odfdecrypt.exceptions import (
    ChecksumError,
    DecompressionError,
    DecryptionError,
    IncorrectPasswordError,
    InvalidODFFileError,
    ManifestParseError,
    ODFDecryptError,
    UnsupportedEncryptionError,
)
from odfdecrypt.odf_origin_detector import ODFOriginDetector, OpenOfficeOrigin

__version__ = version("odfdecrypt")

__all__ = [
    # Decryptors
    "AOODecryptor",
    "LibreOfficeDecryptor",
    # Detector
    "ODFOriginDetector",
    "OpenOfficeOrigin",
    # Utilities
    "is_encrypted",
    # Exceptions
    "ODFDecryptError",
    "InvalidODFFileError",
    "ManifestParseError",
    "UnsupportedEncryptionError",
    "DecryptionError",
    "IncorrectPasswordError",
    "ChecksumError",
    "DecompressionError",
    # Version
    "__version__",
]
