import io
import logging
import xml.etree.ElementTree as ET
import zipfile
from typing import Any, Dict, List

from cryptography.hazmat.primitives import hashes

from odf_decrypt.base_odf_decryptor import BaseODFDecryptor

logger = logging.getLogger(__name__)


class AOODecryptor(BaseODFDecryptor):
    """Apache OpenOffice ODF Decryptor."""

    # Apache OO uses CFB64 (segment_size=64) for Blowfish
    BLOWFISH_SEGMENT_SIZE = 64

    def verify_sha1_checksum(self, data: bytes, expected_checksum: bytes) -> bool:
        """Verify SHA1 checksum of decrypted data (first 1024 bytes)."""
        data_to_hash = data[:1024]
        digest = hashes.Hash(hashes.SHA1(), backend=self.backend)
        digest.update(data_to_hash)
        calculated_checksum = digest.finalize()
        return calculated_checksum == expected_checksum

    def parse_manifest(self, manifest_content: str) -> List[Dict[str, Any]]:
        """Parse encryption parameters from manifest.xml."""
        try:
            root = ET.fromstring(manifest_content)
            encryption_entries = []

            for entry in root.findall(f".//{{{self.NS_MANIFEST}}}file-entry"):
                full_path = self._get_manifest_attr(entry, "full-path")
                if full_path and full_path != "/":
                    encryption_data = self._find_manifest_element(
                        entry, "encryption-data"
                    )
                    if encryption_data is not None:
                        algorithm = self._find_manifest_element(
                            encryption_data, "algorithm"
                        )
                        start_key_gen = self._find_manifest_element(
                            encryption_data, "start-key-generation"
                        )
                        key_derivation = self._find_manifest_element(
                            encryption_data, "key-derivation"
                        )

                        if (
                            algorithm is not None
                            and start_key_gen is not None
                            and key_derivation is not None
                        ):
                            params = {
                                "file_path": full_path,
                                "algorithm_name": self._get_manifest_attr(
                                    algorithm, "algorithm-name"
                                ),
                                "iv": self._parse_base64_attr(
                                    algorithm, "initialisation-vector"
                                ),
                                "start_key_algorithm": self._get_manifest_attr(
                                    start_key_gen, "start-key-generation-name"
                                ),
                                "start_key_size": int(
                                    self._get_manifest_attr(start_key_gen, "key-size")
                                    or 20
                                ),
                                "kdf_name": self._get_manifest_attr(
                                    key_derivation, "key-derivation-name"
                                ),
                                "salt": self._parse_base64_attr(key_derivation, "salt"),
                                "derived_key_size": int(
                                    self._get_manifest_attr(key_derivation, "key-size")
                                    or 16
                                ),
                                "pbkdf2_iterations": int(
                                    self._get_manifest_attr(
                                        key_derivation, "iteration-count"
                                    )
                                    or 1024
                                ),
                                "checksum": self._parse_base64_attr(
                                    encryption_data, "checksum"
                                ),
                                "checksum_type": self._get_manifest_attr(
                                    encryption_data, "checksum-type"
                                ),
                            }
                            encryption_entries.append(params)

            return encryption_entries

        except Exception as e:
            raise ValueError(f"Failed to parse manifest: {e}")

    def _decrypt_file(
        self, zf: zipfile.ZipFile, entry: Dict[str, Any], password: str
    ) -> bytes:
        """Decrypt a single encrypted file."""
        logger.info(f"Decrypting {entry['file_path']}...")

        start_key = self.generate_start_key(
            password, entry["start_key_algorithm"], entry["start_key_size"]
        )

        encryption_key = self.derive_key_pbkdf2(
            start_key,
            entry["salt"],
            entry["pbkdf2_iterations"],
            entry["derived_key_size"],
        )

        encrypted_data = zf.read(entry["file_path"])

        if self._is_blowfish_cfb(entry["algorithm_name"]):
            decrypted_data = self.decrypt_blowfish_cfb(
                encrypted_data,
                encryption_key,
                entry["iv"],
                segment_size=self.BLOWFISH_SEGMENT_SIZE,
            )
        else:
            raise ValueError(
                f"Unsupported encryption algorithm: {entry['algorithm_name']}"
            )

        # Verify checksum if available
        if entry["checksum_type"] == "SHA1/1K" and entry["checksum"]:
            if not self.verify_sha1_checksum(decrypted_data, entry["checksum"]):
                raise ValueError(
                    f"Checksum verification failed for {entry['file_path']}"
                )
            logger.info(f"Checksum verified for {entry['file_path']}")

        # Decompress
        try:
            decompressed = self.decompress_raw_deflate(decrypted_data)
            logger.debug(
                f"Decompressed {entry['file_path']}: "
                f"{len(decrypted_data)} -> {len(decompressed)} bytes"
            )
            return decompressed
        except Exception as e:
            logger.warning(f"Could not decompress {entry['file_path']}: {e}")
            return decrypted_data

    def _update_manifest(
        self,
        out_zf: zipfile.ZipFile,
        encryption_entries: List[Dict[str, Any]],
        original_manifest_content: str,
    ) -> None:
        """Update manifest.xml to remove encryption metadata."""
        root = ET.fromstring(original_manifest_content)
        encrypted_paths = {entry["file_path"] for entry in encryption_entries}

        for entry in root.findall(f".//{{{self.NS_MANIFEST}}}file-entry"):
            full_path = self._get_manifest_attr(entry, "full-path")
            if full_path in encrypted_paths:
                encryption_data = self._find_manifest_element(entry, "encryption-data")
                if encryption_data is not None:
                    entry.remove(encryption_data)

        updated_manifest = ET.tostring(root, encoding="unicode", xml_declaration=True)
        out_zf.writestr("META-INF/manifest.xml", updated_manifest)
        logger.info("Updated manifest.xml - removed encryption metadata")

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
                encryption_entries = self.parse_manifest(manifest_content)

                if not encryption_entries:
                    raise ValueError("No encrypted files found in manifest")

                logger.info(f"Found {len(encryption_entries)} encrypted files")

                decrypted_buffer = io.BytesIO()
                encrypted_paths = {e["file_path"] for e in encryption_entries}

                with zipfile.ZipFile(
                    decrypted_buffer, "w", zipfile.ZIP_DEFLATED
                ) as out_zf:
                    # Copy non-encrypted files (except manifest)
                    for file_info in zf.infolist():
                        if file_info.filename not in encrypted_paths:
                            if (
                                not file_info.filename.endswith("/")
                                and file_info.filename != "META-INF/manifest.xml"
                            ):
                                out_zf.writestr(
                                    file_info.filename, zf.read(file_info.filename)
                                )

                    # Decrypt encrypted files
                    for entry in encryption_entries:
                        decrypted_data = self._decrypt_file(zf, entry, password)
                        out_zf.writestr(entry["file_path"], decrypted_data)

                    # Update manifest
                    self._update_manifest(out_zf, encryption_entries, manifest_content)

                decrypted_buffer.seek(0)
                return decrypted_buffer

        except zipfile.BadZipFile:
            raise ValueError("Invalid ODF file (not a valid ZIP archive)")
        except KeyError as e:
            raise ValueError(f"Missing required file in ODF archive: {e}")
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

    # Backward compatibility aliases
    def decrypt_odf_file(self, odf_path: str, password: str) -> bytes:
        """Decrypt an ODF file and return as bytes."""
        return self.decrypt(odf_path, password).getvalue()

    def decrypt_odf_file_to_bytesio(self, odf_path: str, password: str) -> io.BytesIO:
        """Decrypt an ODF file and return as io.BytesIO object."""
        return self.decrypt(odf_path, password)
