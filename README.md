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

### Basic Usage

Decrypt a file with a password:

```bash
odf-decrypt --file document.odt --password mypassword
```

This creates `document_decrypted.odt` in the same directory.

### Advanced Options

Specify a custom output path:

```bash
odf-decrypt --file document.odt --password mypassword --output decrypted.odt
```

Short options are also available:

```bash
odf-decrypt -f document.odt -p mypassword -o decrypted.odt
```

### Check if File is Encrypted

You can programmatically check if a file is encrypted:

```python
from odfdecrypt import is_encrypted

if is_encrypted("document.odt"):
    print("File is password protected")
else:
    print("File is not encrypted")
```

### Command Line Features

- **Auto-detection**: Automatically detects LibreOffice vs Apache OpenOffice files
- **Fallback support**: Tries LibreOffice first, then Apache OpenOffice if needed
- **Non-encrypted files**: Automatically copies files that aren't encrypted
- **Directory creation**: Creates output directories if they don't exist
- **Error handling**: Provides clear error messages for wrong passwords or corrupted files

### Exit Codes

The CLI returns meaningful exit codes:
- `0`: Success (decryption or copy completed)
- `1`: Error (file not found, wrong password, decryption failed, etc.)

**Note:** If the file is not encrypted, it will simply be copied to the output path with a notification.

## Quick Start

### High-Level API (Recommended)

The simplest way to decrypt ODF files is using the high-level API functions:

```python
from odfdecrypt import decrypt, detect_origin

# Auto-detect origin and decrypt
decrypted_file = decrypt("document.odt", "password")

# Save the decrypted file
with open("decrypted.odt", "wb") as f:
    f.write(decrypted_file.read())
```

### Working with File Objects

You can also work with file objects directly:

```python
import io
from odfdecrypt import decrypt

# Decrypt from BytesIO
with open("document.odt", "rb") as f:
    file_buffer = io.BytesIO(f.read())

decrypted_buffer = decrypt(file_buffer, "password")

# Process the decrypted content without saving to disk
decrypted_content = decrypted_buffer.getvalue()
```

### Origin Detection

Detect the source application before decryption:

```python
from odfdecrypt import detect_origin, OpenOfficeOrigin

origin = detect_origin("document.odt")
print(f"Document created by: {origin}")

# Output: Document created by: OpenOfficeOrigin.LIBREOFFICE
# or: Document created by: OpenOfficeOrigin.APACHE_OPEN_OFFICE
```

### Advanced Usage with Specific Decryptors

For more control, use specific decryptors:

```python
from odfdecrypt import LibreOfficeDecryptor, AOODecryptor

# LibreOffice decryptor
libre_decryptor = LibreOfficeDecryptor()
decrypted_file = libre_decryptor.decrypt("document.odt", "password")

# Apache OpenOffice decryptor
aoo_decryptor = AOODecryptor()
decrypted_file = aoo_decryptor.decrypt("document.odt", "password")
```

### Auto-Detection with Fallback

The high-level API automatically handles fallback scenarios:

```python
from odfdecrypt import decrypt

# This will try LibreOffice first, then Apache OpenOffice if needed
decrypted_file = decrypt("document.odt", "password")

# Works with unknown origins or BytesIO objects
try:
    decrypted = decrypt(io_buffer, "password")
except IncorrectPasswordError:
    print("Wrong password!")
```
```

## API Reference

### High-Level API Functions

#### `decrypt(odf, password)`

Auto-detects the ODF origin and decrypts the file using the appropriate method.

```python
decrypt(odf: str | PathLike | io.BytesIO, password: str) -> io.BytesIO
```

**Parameters:**
- `odf`: Path to ODF file or BytesIO object containing the encrypted file
- `password`: Password to decrypt the file

**Returns:** `io.BytesIO` containing the decrypted ODF file

**Features:**
- Auto-detects LibreOffice vs Apache OpenOffice files
- Works with both file paths and BytesIO objects
- Automatic fallback for unknown origins
- Raises `IncorrectPasswordError` for wrong passwords

#### `detect_origin(file_path)`

Detects whether an ODF file was created by LibreOffice or Apache OpenOffice.

```python
detect_origin(file_path: str | PathLike) -> OpenOfficeOrigin
```

**Parameters:**
- `file_path`: Path to the ODF file

**Returns:** `OpenOfficeOrigin` enum value:
- `OpenOfficeOrigin.LIBREOFFICE`
- `OpenOfficeOrigin.APACHE_OPEN_OFFICE`
- `OpenOfficeOrigin.UNKNOWN`

### Utility Functions

#### `is_encrypted(file_path)`

Checks if an ODF file is password protected.

```python
is_encrypted(file_path: str) -> bool
```

**Parameters:**
- `file_path`: Path to the ODF file

**Returns:** `True` if encrypted, `False` otherwise

### Specialized Decryptors

#### `LibreOfficeDecryptor`

Decrypts ODF files encrypted by LibreOffice (modern and legacy formats).

```python
LibreOfficeDecryptor().decrypt(file_path: str, password: str) -> io.BytesIO
LibreOfficeDecryptor().decrypt_from_bytes(odf: io.BytesIO, password: str) -> io.BytesIO
LibreOfficeDecryptor().decrypt_from_file(odf_path: str, password: str) -> io.BytesIO
```

**Supported Algorithms:**
- Modern: AES-256-GCM with Argon2id key derivation
- Legacy: AES-256-CBC with PBKDF2-SHA1 key derivation

#### `AOODecryptor`

Decrypts ODF files encrypted by Apache OpenOffice.

```python
AOODecryptor().decrypt(file_path: str, password: str) -> io.BytesIO
AOODecryptor().decrypt_from_bytes(odf: io.BytesIO, password: str) -> io.BytesIO
AOODecryptor().decrypt_from_file(odf_path: str, password: str) -> io.BytesIO
```

**Supported Algorithm:**
- Blowfish-CFB with PBKDF2-SHA1 key derivation

#### `ODFOriginDetector`

Advanced origin detection with additional options.

```python
ODFOriginDetector().detect_origin(file_path: str) -> OpenOfficeOrigin
```

**Features:**
- Analyzes manifest.xml and document structure
- Detects application-specific metadata and encryption signatures

## Error Handling

The library provides specific exceptions for different error scenarios:

```python
from odfdecrypt import (
    decrypt,
    IncorrectPasswordError,
    InvalidODFFileError,
    UnsupportedEncryptionError,
    ODFDecryptError
)

try:
    decrypted_file = decrypt("document.odt", "password")
except IncorrectPasswordError:
    print("Wrong password provided")
except InvalidODFFileError:
    print("File is not a valid ODF document")
except UnsupportedEncryptionError:
    print("Encryption format not supported")
except ODFDecryptError as e:
    print(f"Decryption failed: {e}")
```

## Best Practices

### Performance Tips

- **Reuse decryptors**: Create decryptors once and reuse them for multiple files
- **Use BytesIO**: For processing multiple files in memory, use BytesIO objects
- **Check encryption first**: Use `is_encrypted()` to avoid unnecessary decryption attempts

### Security Considerations

- **Password handling**: Never hardcode passwords in your code
- **File validation**: Always validate that files are legitimate ODF documents
- **Memory management**: Properly close file handles and BytesIO objects

```python
from odfdecrypt import decrypt, is_encrypted

# Efficient batch processing
def decrypt_documents(file_paths, password):
    results = []
    for file_path in file_paths:
        if is_encrypted(file_path):
            try:
                decrypted = decrypt(file_path, password)
                results.append(decrypted)
            except Exception as e:
                print(f"Failed to decrypt {file_path}: {e}")
    return results
```

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

## Complete Examples

### Example 1: Simple File Processing

```python
from odfdecrypt import decrypt, is_encrypted

# Process a single file
input_file = "report.odt"
password = "secret123"

if is_encrypted(input_file):
    decrypted_data = decrypt(input_file, password)
    with open("report_decrypted.odt", "wb") as f:
        f.write(decrypted_data.read())
    print("File decrypted successfully")
else:
    print("File is not encrypted")
```

### Example 2: Batch Processing

```python
import os
from odfdecrypt import decrypt, is_encrypted, IncorrectPasswordError

def decrypt_folder(folder_path, password, output_folder="decrypted"):
    """Decrypt all ODF files in a folder."""
    os.makedirs(output_folder, exist_ok=True)

    for filename in os.listdir(folder_path):
        if filename.endswith(('.odt', '.ods', '.odp', '.odg')):
            input_path = os.path.join(folder_path, filename)
            output_path = os.path.join(output_folder, filename)

            if is_encrypted(input_path):
                try:
                    decrypted_data = decrypt(input_path, password)
                    with open(output_path, "wb") as f:
                        f.write(decrypted_data.read())
                    print(f"✓ Decrypted: {filename}")
                except IncorrectPasswordError:
                    print(f"✗ Wrong password for: {filename}")
                except Exception as e:
                    print(f"✗ Failed to decrypt {filename}: {e}")
            else:
                # Copy unencrypted files
                with open(input_path, "rb") as src, open(output_path, "wb") as dst:
                    dst.write(src.read())
                print(f"- Copied (not encrypted): {filename}")

# Usage
decrypt_folder("documents/", "mypassword")
```

### Example 3: Integration with Document Processing

```python
import io
import sharepoint2text
from odfdecrypt import decrypt

def extract_text_from_encrypted_odf(file_path, password):
    """Extract text from an encrypted ODF file."""
    try:
        # Decrypt the file
        decrypted_buffer = decrypt(file_path, password)

        # Process with sharepoint2text
        document = next(sharepoint2text.read_odt(decrypted_buffer))
        return document.get_full_text()
    except Exception as e:
        return f"Error processing file: {e}"

# Usage
text = extract_text_from_encrypted_odf("document.odt", "password")
print(f"Document content: {text}")
```

### Example 4: Advanced Origin Detection

```python
from odfdecrypt import detect_origin, OpenOfficeOrigin, decrypt

def smart_decrypt(file_path, password):
    """Decrypt with detailed origin information."""
    origin = detect_origin(file_path)

    origin_info = {
        OpenOfficeOrigin.LIBREOFFICE: "LibreOffice (supports modern AES-256-GCM)",
        OpenOfficeOrigin.APACHE_OPEN_OFFICE: "Apache OpenOffice (supports Blowfish-CFB)",
        OpenOfficeOrigin.UNKNOWN: "Unknown origin (will attempt both methods)"
    }

    print(f"Detected origin: {origin_info.get(origin, 'Unknown')}")

    try:
        decrypted_data = decrypt(file_path, password)
        print("✓ Decryption successful")
        return decrypted_data
    except Exception as e:
        print(f"✗ Decryption failed: {e}")
        raise

# Usage
try:
    decrypted = smart_decrypt("mystery_document.odt", "password")
    with open("output.odt", "wb") as f:
        f.write(decrypted.read())
except Exception as e:
    print(f"Could not process document: {e}")
```

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
