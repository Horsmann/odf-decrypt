import io
import logging
import os
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from typing import Any, Dict, List, Tuple

import argon2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from odf_decrypt.base_odf_decryptor import BaseODFDecryptor

logger = logging.getLogger(__name__)


class LibreOfficeDecryptor(BaseODFDecryptor):
    """Decryptor for LibreOffice ODF files supporting both modern and legacy formats."""

    # LibreOffice-specific algorithm URLs
    ALGO_AES256_GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
    ALGO_AES256_CBC = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"

    # LibreOffice-specific KDF
    KDF_ARGON2ID = (
        "urn:org:documentfoundation:names:experimental:office:manifest:argon2id"
    )

    # LibreOffice extension namespace
    NS_LOEXT = "urn:org:documentfoundation:names:experimental:office:xmlns:loext:1.0"

    def derive_key_argon2id(
        self,
        start_key: bytes,
        salt: bytes,
        iterations: int,
        memory: int,
        lanes: int,
        key_size: int,
    ) -> bytes:
        """Derive encryption key using Argon2id."""
        try:
            return argon2.low_level.hash_secret_raw(
                secret=start_key,
                salt=salt,
                time_cost=iterations,
                memory_cost=memory,
                parallelism=lanes,
                hash_len=key_size,
                type=argon2.low_level.Type.ID,
            )
        except Exception as e:
            raise ValueError(f"Argon2id key derivation failed: {e}")

    def decrypt_aes256_gcm(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypt using AES-256-GCM."""
        if len(key) != 32:
            raise ValueError(f"AES-256 requires 32-byte key, got {len(key)}")
        if len(iv) != 12:
            raise ValueError(f"AES-GCM requires 12-byte IV, got {len(iv)}")

        # Check for prepended IV (LibreOffice format)
        if len(data) > 12 and data[:12] == iv:
            encrypted_data = data[12:]
        else:
            encrypted_data = data

        if len(encrypted_data) < 16:
            raise ValueError("Encrypted data too short to contain GCM tag")

        actual_ciphertext = encrypted_data[:-16]
        tag = encrypted_data[-16:]

        aesgcm = AESGCM(key)
        return aesgcm.decrypt(iv, actual_ciphertext + tag, None)

    def decrypt_aes256_cbc(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypt using AES-256-CBC."""
        if len(key) != 32:
            raise ValueError(f"AES-256 requires 32-byte key, got {len(key)}")
        if len(iv) != 16:
            raise ValueError(f"AES-CBC requires 16-byte IV, got {len(iv)}")

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        # Remove PKCS7 padding
        padding_length = plaintext[-1]
        if padding_length > 16 or padding_length == 0:
            raise ValueError("Invalid PKCS7 padding")
        return plaintext[:-padding_length]

    def _derive_encryption_key(self, start_key: bytes, params: Dict[str, Any]) -> bytes:
        """Derive encryption key based on KDF parameters."""
        kdf_name = params["kdf_name"]

        if kdf_name == self.KDF_ARGON2ID:
            return self.derive_key_argon2id(
                start_key,
                params["salt"],
                params["argon2_iterations"],
                params["argon2_memory"],
                params["argon2_lanes"],
                params["derived_key_size"],
            )
        elif self._is_pbkdf2(kdf_name):
            return self.derive_key_pbkdf2(
                start_key,
                params["salt"],
                params["pbkdf2_iterations"],
                params["derived_key_size"],
            )
        else:
            raise ValueError(f"Unsupported key derivation function: {kdf_name}")

    def _decrypt_data(
        self, encrypted_data: bytes, key: bytes, params: Dict[str, Any]
    ) -> bytes:
        """Decrypt data based on algorithm parameters."""
        algo = params["algorithm_name"]
        iv = params["iv"]

        if algo == self.ALGO_AES256_GCM:
            return self.decrypt_aes256_gcm(encrypted_data, key, iv)
        elif algo == self.ALGO_AES256_CBC:
            return self.decrypt_aes256_cbc(encrypted_data, key, iv)
        elif self._is_blowfish_cfb(algo):
            return self.decrypt_blowfish_cfb(encrypted_data, key, iv, segment_size=8)
        else:
            raise ValueError(f"Unsupported encryption algorithm: {algo}")

    def _parse_encryption_entry(
        self, entry: ET.Element, is_modern: bool
    ) -> Dict[str, Any]:
        """Parse encryption parameters from a file entry element."""
        encryption_data = self._find_manifest_element(entry, "encryption-data")
        if encryption_data is None:
            raise ValueError("No encryption-data found")

        algorithm = self._find_manifest_element(encryption_data, "algorithm")
        start_key_gen = self._find_manifest_element(
            encryption_data, "start-key-generation"
        )
        key_derivation = self._find_manifest_element(encryption_data, "key-derivation")

        if algorithm is None or start_key_gen is None or key_derivation is None:
            raise ValueError("Missing required encryption parameters")

        # Default key sizes differ between modern and legacy formats
        default_start_key_size = 32 if is_modern else 20
        default_derived_key_size = 32 if is_modern else 16

        params = {
            "file_path": self._get_manifest_attr(entry, "full-path"),
            "algorithm_name": self._get_manifest_attr(algorithm, "algorithm-name"),
            "iv": self._parse_base64_attr(algorithm, "initialisation-vector"),
            "start_key_algorithm": self._get_manifest_attr(
                start_key_gen, "start-key-generation-name"
            ),
            "start_key_size": int(
                self._get_manifest_attr(start_key_gen, "key-size")
                or default_start_key_size
            ),
            "kdf_name": self._get_manifest_attr(key_derivation, "key-derivation-name"),
            "salt": self._parse_base64_attr(key_derivation, "salt"),
            "derived_key_size": int(
                self._get_manifest_attr(key_derivation, "key-size")
                or default_derived_key_size
            ),
        }

        # Parse KDF-specific parameters
        kdf_name = params["kdf_name"]
        if kdf_name == self.KDF_ARGON2ID:
            params["argon2_iterations"] = int(
                key_derivation.get(f"{{{self.NS_LOEXT}}}argon2-iterations", 3)
            )
            params["argon2_memory"] = int(
                key_derivation.get(f"{{{self.NS_LOEXT}}}argon2-memory", 65536)
            )
            params["argon2_lanes"] = int(
                key_derivation.get(f"{{{self.NS_LOEXT}}}argon2-lanes", 4)
            )
        elif self._is_pbkdf2(kdf_name):
            params["pbkdf2_iterations"] = int(
                self._get_manifest_attr(key_derivation, "iteration-count") or 1024
            )

        return params

    def parse_manifest(self, manifest_content: str) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Parse manifest.xml to extract encryption parameters.

        Returns:
            Tuple of (format_type, encryption_entries)
            format_type: 'modern' (single encrypted-package) or 'legacy' (individual files)
        """
        try:
            root = ET.fromstring(manifest_content)

            # Look for modern format (single encrypted-package)
            for entry in root.findall(f".//{{{self.NS_MANIFEST}}}file-entry"):
                if self._get_manifest_attr(entry, "full-path") == "encrypted-package":
                    params = self._parse_encryption_entry(entry, is_modern=True)
                    return "modern", [params]

            # Legacy format with individual encrypted files
            encryption_entries = []
            for entry in root.findall(f".//{{{self.NS_MANIFEST}}}file-entry"):
                full_path = self._get_manifest_attr(entry, "full-path")
                if full_path and full_path != "/":
                    encryption_data = self._find_manifest_element(
                        entry, "encryption-data"
                    )
                    if encryption_data is not None:
                        try:
                            params = self._parse_encryption_entry(
                                entry, is_modern=False
                            )
                            encryption_entries.append(params)
                        except ValueError:
                            continue

            return "legacy", encryption_entries

        except Exception as e:
            logger.debug(f"Exception in parse_manifest: {e}", exc_info=True)
            raise ValueError(f"Failed to parse manifest: {e}")

    def _decrypt_modern_format(
        self, zf: zipfile.ZipFile, params: Dict[str, Any], password: str
    ) -> bytes:
        """Decrypt modern format (single encrypted-package file)."""
        logger.info("Modern format detected - single encrypted package")

        encrypted_data = zf.read("encrypted-package")
        logger.debug(f"Encrypted package size: {len(encrypted_data)} bytes")

        start_key = self.generate_start_key(
            password, params["start_key_algorithm"], params["start_key_size"]
        )
        encryption_key = self._derive_encryption_key(start_key, params)
        logger.debug(f"Decrypting with {params['algorithm_name']}...")

        decrypted_compressed = self._decrypt_data(
            encrypted_data, encryption_key, params
        )

        # Decompress (LibreOffice uses raw deflate)
        try:
            plaintext = self.decompress_raw_deflate(decrypted_compressed)
            logger.debug(f"Decompression successful: {len(plaintext)} bytes")
        except Exception as e:
            logger.warning(f"Decompression failed: {e}")
            plaintext = decrypted_compressed

        return plaintext

    def _decrypt_legacy_format(
        self,
        zf: zipfile.ZipFile,
        encryption_entries: List[Dict[str, Any]],
        password: str,
    ) -> bytes:
        """Decrypt legacy format (individual encrypted files)."""
        logger.info(
            f"Legacy format detected - {len(encryption_entries)} encrypted files"
        )

        encrypted_paths = {entry["file_path"] for entry in encryption_entries}

        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w") as out_zf:
                # Copy non-encrypted files
                for file_info in zf.infolist():
                    if file_info.filename not in encrypted_paths:
                        if not file_info.filename.endswith("/"):
                            out_zf.writestr(
                                file_info.filename, zf.read(file_info.filename)
                            )

                # Decrypt each encrypted file
                for entry in encryption_entries:
                    logger.info(f"Decrypting {entry['file_path']}...")
                    start_key = self.generate_start_key(
                        password,
                        entry["start_key_algorithm"],
                        entry["start_key_size"],
                    )
                    encryption_key = self._derive_encryption_key(start_key, entry)
                    encrypted_data = zf.read(entry["file_path"])
                    decrypted_data = self._decrypt_data(
                        encrypted_data, encryption_key, entry
                    )
                    out_zf.writestr(entry["file_path"], decrypted_data)

            with open(tmp.name, "rb") as f:
                plaintext = f.read()
            os.unlink(tmp.name)

        return plaintext

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
        try:
            with zipfile.ZipFile(odf_path, "r") as zf:
                manifest_content = self._read_manifest(zf)
                encryption_format, encryption_entries = self.parse_manifest(
                    manifest_content
                )
                logger.info(f"Detected {encryption_format} encryption format")

                if encryption_format == "modern":
                    plaintext = self._decrypt_modern_format(
                        zf, encryption_entries[0], password
                    )
                else:
                    plaintext = self._decrypt_legacy_format(
                        zf, encryption_entries, password
                    )

                return io.BytesIO(plaintext)

        except zipfile.BadZipFile:
            raise ValueError("Invalid ODF file (not a valid ZIP archive)")
        except KeyError as e:
            raise ValueError(f"Missing required file in ODF archive: {e}")
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
