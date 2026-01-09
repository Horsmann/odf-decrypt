"""
Command-line interface for odf-decrypt.
"""

import argparse
import os
import shutil
import sys
import zipfile

from odfdecrypt.decryption.apache_odf_decryptor import AOODecryptor
from odfdecrypt.decryption.libre_office_odf_decryptor import LibreOfficeDecryptor
from odfdecrypt.odf_origin_detector import ODFOriginDetector, OpenOfficeOrigin


def is_encrypted(file_path: str) -> bool:
    """
    Check if an ODF file is encrypted.

    Args:
        file_path: Path to the ODF file

    Returns:
        True if the file is encrypted, False otherwise
    """
    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            if "META-INF/manifest.xml" not in zf.namelist():
                return False

            manifest_content = zf.read("META-INF/manifest.xml").decode("utf-8")

            # Check for encryption indicators in manifest
            encryption_indicators = [
                "encryption-data",
                "encrypted-package",
                "algorithm-name",
                "key-derivation",
            ]

            for indicator in encryption_indicators:
                if indicator in manifest_content:
                    return True

            return False
    except (zipfile.BadZipFile, Exception):
        return False


def get_default_output_path(input_path: str) -> str:
    """
    Generate default output path by adding _decrypted suffix before extension.

    Args:
        input_path: Path to the input file

    Returns:
        Output path with _decrypted suffix
    """
    base, ext = os.path.splitext(input_path)
    return f"{base}_decrypted{ext}"


def decrypt_file(file_path: str, password: str, output_path: str) -> bool:
    """
    Decrypt an ODF file and save to output path.

    Args:
        file_path: Path to the encrypted ODF file
        password: Password to decrypt the file
        output_path: Path to save the decrypted file

    Returns:
        True if decryption was successful, False otherwise
    """
    detector = ODFOriginDetector()
    origin = detector.detect_origin(file_path)

    try:
        if origin == OpenOfficeOrigin.LIBREOFFICE:
            decryptor = LibreOfficeDecryptor()
        elif origin == OpenOfficeOrigin.APACHE_OPEN_OFFICE:
            decryptor = AOODecryptor()
        else:
            # Try LibreOffice first, then Apache OpenOffice
            try:
                decryptor = LibreOfficeDecryptor()
                decrypted = decryptor.decrypt(file_path, password)
                with open(output_path, "wb") as f:
                    f.write(decrypted.read())
                return True
            except Exception:
                decryptor = AOODecryptor()

        decrypted = decryptor.decrypt(file_path, password)
        with open(output_path, "wb") as f:
            f.write(decrypted.read())
        return True

    except Exception as e:
        print(f"Error decrypting file: {e}", file=sys.stderr)
        return False


def main(args: list[str] | None = None) -> int:
    """
    Main entry point for the CLI.

    Args:
        args: Command line arguments (defaults to sys.argv[1:])

    Returns:
        Exit code (0 for success, 1 for error)
    """
    parser = argparse.ArgumentParser(
        prog="odf-decrypt",
        description="Decrypt password-protected OpenDocument Format (ODF) files",
    )
    parser.add_argument(
        "--file",
        "-f",
        required=True,
        help="Path to the encrypted ODF file",
    )
    parser.add_argument(
        "--password",
        "-p",
        required=True,
        help="Password to decrypt the file",
    )
    parser.add_argument(
        "--output",
        "-o",
        required=False,
        help="Output path for the decrypted file (default: <filename>_decrypted.<ext>)",
    )

    parsed_args = parser.parse_args(args)

    file_path = parsed_args.file
    password = parsed_args.password
    output_path = parsed_args.output or get_default_output_path(file_path)

    # Check if input file exists
    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}", file=sys.stderr)
        return 1

    # Create output directory if it doesn't exist
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError as e:
            print(f"Error: Failed to create output directory: {e}", file=sys.stderr)
            return 1

    # Check if file is encrypted
    if not is_encrypted(file_path):
        # File is not encrypted, just copy it
        shutil.copy2(file_path, output_path)
        print(f"File is not encrypted. Copied to: {output_path}")
        return 0

    # Decrypt the file
    if decrypt_file(file_path, password, output_path):
        print(f"Successfully decrypted to: {output_path}")
        return 0
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main())
