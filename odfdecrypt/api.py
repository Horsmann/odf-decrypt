"""
Convenience API wrappers for common odfdecrypt workflows.
"""

from __future__ import annotations

import io
import zipfile
from os import PathLike

from odfdecrypt.decryption.apache_odf_decryptor import AOODecryptor
from odfdecrypt.decryption.libre_office_odf_decryptor import LibreOfficeDecryptor
from odfdecrypt.exceptions import IncorrectPasswordError
from odfdecrypt.odf_origin_detector import ODFOriginDetector, OpenOfficeOrigin


def detect_origin(file_path: str | PathLike) -> OpenOfficeOrigin:
    """Detect an ODF's origin without instantiating ODFOriginDetector."""
    return ODFOriginDetector().detect_origin(str(file_path))


def _is_encrypted_bytes(odf: io.BytesIO) -> bool:
    try:
        odf.seek(0)
        with zipfile.ZipFile(odf, "r") as zf:
            if "META-INF/manifest.xml" not in zf.namelist():
                return False

            manifest_content = zf.read("META-INF/manifest.xml").decode("utf-8")
            encryption_indicators = [
                "encryption-data",
                "encrypted-package",
                "algorithm-name",
                "key-derivation",
            ]
            return any(
                indicator in manifest_content for indicator in encryption_indicators
            )
    except Exception:
        return False


def decrypt(odf: str | PathLike | io.BytesIO, password: str) -> io.BytesIO:
    """
    Decrypt an ODF by auto-detecting whether it was created by LibreOffice or AOO.

    If origin is UNKNOWN (or if input is a BytesIO), LibreOffice is attempted first,
    then Apache OpenOffice as a fallback.
    """
    if isinstance(odf, io.BytesIO):
        odf.seek(0)
        try:
            decrypted = LibreOfficeDecryptor().decrypt(odf, password)
            if not _is_encrypted_bytes(decrypted):
                return decrypted
        except IncorrectPasswordError:
            raise
        except Exception:
            pass
        odf.seek(0)
        return AOODecryptor().decrypt(odf, password)

    origin = detect_origin(odf)

    if origin == OpenOfficeOrigin.LIBREOFFICE:
        return LibreOfficeDecryptor().decrypt(odf, password)
    if origin == OpenOfficeOrigin.APACHE_OPEN_OFFICE:
        return AOODecryptor().decrypt(odf, password)

    try:
        decrypted = LibreOfficeDecryptor().decrypt(odf, password)
        if not _is_encrypted_bytes(decrypted):
            return decrypted
    except IncorrectPasswordError:
        raise
    except Exception:
        pass
    return AOODecryptor().decrypt(odf, password)


decrypt_auto = decrypt
