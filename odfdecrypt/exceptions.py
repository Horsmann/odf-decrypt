"""
Custom exceptions and warnings for odf-decrypt.
"""


class NotEncryptedWarning(UserWarning):
    """Warning issued when attempting to decrypt a file that is not encrypted."""

    pass


class ODFDecryptError(Exception):
    """Base exception for all ODF decryption errors."""

    pass


class InvalidODFFileError(ODFDecryptError):
    """Raised when the input file is not a valid ODF file."""

    pass


class ManifestParseError(ODFDecryptError):
    """Raised when the manifest.xml cannot be parsed or is invalid."""

    pass


class UnsupportedEncryptionError(ODFDecryptError):
    """Raised when an unsupported encryption algorithm or configuration is encountered."""

    pass


class DecryptionError(ODFDecryptError):
    """Raised when decryption fails due to wrong password or corrupted data."""

    pass


class IncorrectPasswordError(DecryptionError):
    """Raised when the provided password is incorrect."""

    pass


class ChecksumError(DecryptionError):
    """Raised when checksum verification fails after decryption."""

    pass


class DecompressionError(DecryptionError):
    """Raised when decompression of decrypted data fails."""

    pass
