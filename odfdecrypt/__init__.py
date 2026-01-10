"""
odf-decrypt: Decrypt password-protected OpenDocument Format (ODF) files.

This library supports decryption of ODF files created by both LibreOffice
and Apache OpenOffice, handling modern (AES-256-GCM, Argon2id) and legacy
(Blowfish-CFB, PBKDF2) encryption formats.
"""

from importlib.metadata import version

from odfdecrypt.api import decrypt, detect_origin
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
    NotEncryptedWarning,
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
    "detect_origin",
    # Utilities
    "is_encrypted",
    "decrypt",
    # Exceptions
    "ODFDecryptError",
    "InvalidODFFileError",
    "ManifestParseError",
    "UnsupportedEncryptionError",
    "DecryptionError",
    "IncorrectPasswordError",
    "ChecksumError",
    "DecompressionError",
    # Warnings
    "NotEncryptedWarning",
    # Version
    "__version__",
]
