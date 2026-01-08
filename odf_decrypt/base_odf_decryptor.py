import base64
import io
import logging
import xml.etree.ElementTree as ET
import zipfile
import zlib
from typing import Optional

from Crypto.Cipher import Blowfish as CryptoBlowfish
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)


class BaseODFDecryptor:
    """Base class for ODF decryptors with shared functionality."""

    # XML Namespaces
    NS_MANIFEST = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"

    # Algorithm identifiers (URL format)
    ALGO_BLOWFISH_CFB = (
        "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#blowfish-cfb8"
    )

    # Key derivation identifiers
    KDF_PBKDF2 = "http://www.w3.org/2001/04/xmlenc#pbkdf2"

    # Start key generation identifiers
    START_KEY_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
    START_KEY_SHA1 = "http://www.w3.org/2001/04/xmlenc#sha1"

    # Legacy format names (simple strings)
    ALGO_BLOWFISH_CFB_LEGACY = "Blowfish CFB"
    KDF_PBKDF2_LEGACY = "PBKDF2"
    START_KEY_SHA1_LEGACY = "SHA1"

    # ODF MIME type mappings (comprehensive list)
    ODF_MIME_TYPES = {
        "application/vnd.oasis.opendocument.text": ".odt",
        "application/vnd.oasis.opendocument.text-template": ".ott",
        "application/vnd.oasis.opendocument.text-web": ".oth",
        "application/vnd.oasis.opendocument.text-master": ".odm",
        "application/vnd.oasis.opendocument.graphics": ".odg",
        "application/vnd.oasis.opendocument.graphics-template": ".otg",
        "application/vnd.oasis.opendocument.presentation": ".odp",
        "application/vnd.oasis.opendocument.presentation-template": ".otp",
        "application/vnd.oasis.opendocument.spreadsheet": ".ods",
        "application/vnd.oasis.opendocument.spreadsheet-template": ".ots",
        "application/vnd.oasis.opendocument.chart": ".odc",
        "application/vnd.oasis.opendocument.formula": ".odf",
        "application/vnd.oasis.opendocument.database": ".odb",
        "application/vnd.oasis.opendocument.image": ".odi",
    }

    def __init__(self):
        self.backend = default_backend()

    def generate_start_key(self, password: str, algorithm: str, key_size: int) -> bytes:
        """Generate start key from password using the specified algorithm."""
        password_bytes = password.encode("utf-8")

        if algorithm in (self.START_KEY_SHA256,):
            digest = hashes.Hash(hashes.SHA256(), backend=self.backend)
            digest.update(password_bytes)
            return digest.finalize()[:key_size]
        elif algorithm in (self.START_KEY_SHA1, self.START_KEY_SHA1_LEGACY):
            digest = hashes.Hash(hashes.SHA1(), backend=self.backend)
            digest.update(password_bytes)
            return digest.finalize()[:key_size]
        else:
            raise ValueError(f"Unsupported start key algorithm: {algorithm}")

    def derive_key_pbkdf2(
        self, password: bytes, salt: bytes, iterations: int, key_size: int
    ) -> bytes:
        """Derive encryption key using PBKDF2-SHA1."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=key_size,
            salt=salt,
            iterations=iterations,
            backend=self.backend,
        )
        return kdf.derive(password)

    def decrypt_blowfish_cfb(
        self, ciphertext: bytes, key: bytes, iv: bytes, segment_size: int = 8
    ) -> bytes:
        """
        Decrypt using Blowfish-CFB.

        Args:
            ciphertext: Encrypted data
            key: Encryption key
            iv: Initialization vector (must be 8 bytes)
            segment_size: CFB segment size in bits (8 for CFB8, 64 for CFB64)

        Returns:
            Decrypted data
        """
        if len(iv) != 8:
            raise ValueError(f"Blowfish-CFB requires 8-byte IV, got {len(iv)}")

        cipher = CryptoBlowfish.new(
            key, CryptoBlowfish.MODE_CFB, iv, segment_size=segment_size
        )
        return cipher.decrypt(ciphertext)

    def decompress_raw_deflate(self, compressed_data: bytes) -> bytes:
        """Decompress raw deflate data (no zlib header)."""
        try:
            return zlib.decompress(compressed_data, -zlib.MAX_WBITS)
        except Exception as e:
            raise ValueError(f"Raw deflate decompression failed: {e}")

    def _get_manifest_attr(self, element: ET.Element, attr_name: str) -> Optional[str]:
        """Get attribute value from manifest element with proper namespace."""
        return element.get(f"{{{self.NS_MANIFEST}}}{attr_name}")

    def _find_manifest_element(
        self, parent: ET.Element, tag_name: str
    ) -> Optional[ET.Element]:
        """Find child element in manifest with proper namespace."""
        return parent.find(f"{{{self.NS_MANIFEST}}}{tag_name}")

    def _parse_base64_attr(
        self, element: ET.Element, attr_name: str
    ) -> Optional[bytes]:
        """Parse base64-encoded attribute value."""
        value = self._get_manifest_attr(element, attr_name)
        if value:
            return base64.b64decode(value)
        return None

    def _is_pbkdf2(self, kdf_name: str) -> bool:
        """Check if the KDF name indicates PBKDF2."""
        return kdf_name in (self.KDF_PBKDF2, self.KDF_PBKDF2_LEGACY)

    def _is_blowfish_cfb(self, algo_name: str) -> bool:
        """Check if the algorithm name indicates Blowfish CFB."""
        return algo_name in (self.ALGO_BLOWFISH_CFB, self.ALGO_BLOWFISH_CFB_LEGACY)

    def _read_manifest(self, zf: zipfile.ZipFile) -> str:
        """Read and return manifest.xml content from ZIP file."""
        return zf.read("META-INF/manifest.xml").decode("utf-8")

    def decrypt(self, odf_path: str, password: str) -> io.BytesIO:
        """
        Decrypt an ODF file using the provided password.

        Args:
            odf_path: Path to the encrypted ODF file
            password: Password to decrypt the file

        Returns:
            Decrypted ODF ZIP archive as io.BytesIO object

        Raises:
            ValueError: If decryption fails
        """
        raise NotImplementedError("Subclasses must implement decrypt()")
