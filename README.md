# odf-decrypt

[![PyPI version](https://badge.fury.io/py/odf-decrypt.svg)](https://badge.fury.io/py/odf-decrypt)
[![Python Versions](https://img.shields.io/pypi/pyversions/odf-decrypt.svg)](https://pypi.org/project/odf-decrypt/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A Python library for decrypting password-protected OpenDocument Format (ODF) files. Supports files created by both **LibreOffice** and **Apache OpenOffice**, handling modern and legacy encryption formats. Currently supports regular password encryption only - GPG key encryption is not yet implemented.

## Features

- **Command-Line Tool**: Simple CLI for quick decryption tasks
- **Dual Application Support**: Decrypt files from both LibreOffice and Apache OpenOffice
- **Modern Encryption**: AES-256-GCM with Argon2id key derivation (LibreOffice)
- **Legacy Encryption**: Blowfish-CFB with PBKDF2-SHA1 (Apache OpenOffice)
- **Automatic Detection**: Identifies the source application and encryption format
- **All ODF Types**: Supports `.odt`, `.ods`, `.odp`, `.odg`, `.odf`, and more
- **Password Encryption Only**: Currently supports regular password-protected files (GPG key encryption not yet supported)

## Supported Encryption Formats

| Application | Algorithm | Key Derivation | Status |
|-------------|-----------|----------------|--------|
| LibreOffice (modern) | AES-256-GCM | Argon2id | Supported |
| LibreOffice (legacy) | AES-256-CBC | PBKDF2-SHA1 | Supported |
| Apache OpenOffice | Blowfish-CFB | PBKDF2-SHA1 | Supported |

## Installation

```bash
pip install odf-decrypt
```

Or with [uv](https://github.com/astral-sh/uv):

```bash
uv add odf-decrypt
```

## Command-Line Usage

Decrypt a file with a password:

```bash
odf-decrypt --file document.odt --password mypassword
```

This creates `document_decrypted.odt` in the same directory.

Specify a custom output path:

```bash
odf-decrypt --file document.odt --password mypassword --output decrypted.odt
```

Short options are also available:

```bash
odf-decrypt -f document.odt -p mypassword -o decrypted.odt
```

**Note:** If the file is not encrypted, it will simply be copied to the output path.

## Quick Start

### Decrypt a LibreOffice file

```python
from odfdecrypt import LibreOfficeDecryptor

decryptor = LibreOfficeDecryptor()
decrypted_file = decryptor.decrypt("document.odt", "password")

# Save the decrypted file
with open("decrypted.odt", "wb") as f:
    f.write(decrypted_file.read())
```

### Decrypt an Apache OpenOffice file

```python
from odfdecrypt import AOODecryptor

decryptor = AOODecryptor()
decrypted_file = decryptor.decrypt("document.odt", "password")

# Save the decrypted file
with open("decrypted.odt", "wb") as f:
    f.write(decrypted_file.read())
```

### Auto-detect and decrypt

```python
from odfdecrypt import ODFOriginDetector, OpenOfficeOrigin
from odfdecrypt import LibreOfficeDecryptor, AOODecryptor

# Detect the source application
detector = ODFOriginDetector()
origin = detector.detect_origin("document.odt")

# Use the appropriate decryptor
if origin == OpenOfficeOrigin.LIBREOFFICE:
    decryptor = LibreOfficeDecryptor()
elif origin == OpenOfficeOrigin.APACHE_OPEN_OFFICE:
    decryptor = AOODecryptor()
else:
    raise ValueError("Unknown document origin")

decrypted_file = decryptor.decrypt("document.odt", "password")
```

## API Reference

### `LibreOfficeDecryptor`

Decrypts ODF files encrypted by LibreOffice.

```python
LibreOfficeDecryptor().decrypt(file_path: str, password: str) -> io.BytesIO
```

**Parameters:**
- `file_path`: Path to the encrypted ODF file
- `password`: Password to decrypt the file

**Returns:** `io.BytesIO` containing the decrypted ODF file

### `AOODecryptor`

Decrypts ODF files encrypted by Apache OpenOffice.

```python
AOODecryptor().decrypt(file_path: str, password: str) -> io.BytesIO
```

**Parameters:**
- `file_path`: Path to the encrypted ODF file
- `password`: Password to decrypt the file

**Returns:** `io.BytesIO` containing the decrypted ODF file

### `ODFOriginDetector`

Detects whether an ODF file was created by LibreOffice or Apache OpenOffice.

```python
ODFOriginDetector().detect_origin(file_path: str) -> OpenOfficeOrigin
```

**Parameters:**
- `file_path`: Path to the ODF file

**Returns:** `OpenOfficeOrigin` enum value:
- `OpenOfficeOrigin.LIBREOFFICE`
- `OpenOfficeOrigin.APACHE_OPEN_OFFICE`
- `OpenOfficeOrigin.UNKNOWN`

## Supported File Types

| Extension | Type |
|-----------|------|
| `.odt` | Text Document |
| `.ods` | Spreadsheet |
| `.odp` | Presentation |
| `.odg` | Drawing |
| `.odf` | Formula |
| `.odb` | Database |
| `.odc` | Chart |
| `.odm` | Master Document |
| `.ott` | Text Template |
| `.ots` | Spreadsheet Template |
| `.otp` | Presentation Template |
| `.otg` | Drawing Template |

## Requirements

- Python 3.10+
- cryptography
- pycryptodome
- argon2-cffi

## Development

### Setup

```bash
git clone https://github.com/toobee/odf-decrypt.git
cd odf-decrypt
uv sync --all-groups
```

### Run tests

```bash
uv run pytest
```

### Code formatting

```bash
uv run black .
```

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
