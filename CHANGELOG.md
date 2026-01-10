# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of odfdecrypt
- **LibreOffice decryption support**:
  - Modern format: AES-256-GCM with Argon2id key derivation
  - Legacy format: AES-256-CBC with PBKDF2-SHA1 key derivation
- **Apache OpenOffice decryption support**:
  - Blowfish-CFB with PBKDF2-SHA1 key derivation
- **Origin detection**: Automatic detection of source application (LibreOffice vs Apache OpenOffice)
- **Command-line interface** (`odfdecrypt`):
  - Decrypt files with `--file` and `--password` options
  - Custom output path with `--output`
  - Auto-detection and fallback between decryption methods
  - Automatic handling of non-encrypted files (copies them)
- **High-level API**:
  - `decrypt(odf, password)` - Auto-detects origin and decrypts ODF files
  - `detect_origin(file_path)` - Detects whether file is from LibreOffice or Apache OpenOffice
  - Support for both file paths and `BytesIO` objects with automatic fallback
- **Low-level API**:
  - `LibreOfficeDecryptor` class for LibreOffice files
  - `AOODecryptor` class for Apache OpenOffice files
  - `ODFOriginDetector` class for origin detection
  - `is_encrypted()` utility function
- **Comprehensive exception hierarchy**:
  - `ODFDecryptError` (base exception)
  - `InvalidODFFileError`
  - `ManifestParseError`
  - `UnsupportedEncryptionError`
  - `DecryptionError`
  - `IncorrectPasswordError`
  - `ChecksumError`
  - `DecompressionError`
- **Warnings**:
  - `NotEncryptedWarning` - Issued when attempting to decrypt a non-encrypted file (returns original content gracefully)
- Support for all ODF file types: `.odt`, `.ods`, `.odp`, `.odg`, `.odf`, `.odb`, `.odc`, `.odm`, and templates
- GitHub Actions workflows for automated testing and publishing
- Multi-version Python testing (3.10, 3.11, 3.12, 3.13, 3.14)

[Unreleased]: https://github.com/toobee/odf-decrypt/commits/main
