import xml.etree.ElementTree as ET
import zipfile
from enum import Enum, auto
from typing import Dict


class OpenOfficeOrigin(Enum):
    UNKNOWN = auto()
    APACHE_OPEN_OFFICE = auto()
    LIBREOFFICE = auto()


class ODFOriginDetector:
    """Detects whether an ODF file originates from LibreOffice or Apache OpenOffice."""

    def __init__(self):
        pass

    def analyze_manifest_structure(self, zf: zipfile.ZipFile) -> Dict[str, any]:
        """Analyze the manifest.xml structure for origin indicators."""
        try:
            manifest_content = zf.read("META-INF/manifest.xml").decode("utf-8")
            root = ET.fromstring(manifest_content)

            ns_manifest = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"

            analysis = {
                "has_encrypted_package": False,
                "encrypted_files": [],
                "encryption_algorithms": [],
                "key_derivation_methods": [],
                "checksum_types": [],
                "libreoffice_namespaces": [],
                "manifest_version": root.get("manifest:version", "unknown"),
            }

            # Check for LibreOffice-specific namespaces
            namespaces = dict(
                [
                    node
                    for _, node in ET.iterparse(
                        zipfile.Path(zf, "META-INF/manifest.xml").open(),
                        events=["start-ns"],
                    )
                ]
            )

            for ns_prefix, ns_uri in namespaces.items():
                if "documentfoundation" in ns_uri or "loext" in ns_uri:
                    analysis["libreoffice_namespaces"].append(ns_uri)

            # Look for encrypted package (LibreOffice modern format)
            for entry in root.findall(f".//{{{ns_manifest}}}file-entry"):
                full_path = entry.get(f"{{{ns_manifest}}}full-path")

                if full_path == "encrypted-package":
                    analysis["has_encrypted_package"] = True
                    encryption_data = entry.find(f"{{{ns_manifest}}}encryption-data")
                    if encryption_data is not None:
                        self._extract_encryption_info(
                            encryption_data, analysis, ns_manifest
                        )

                # Check individual file encryption
                encryption_data = entry.find(f"{{{ns_manifest}}}encryption-data")
                if encryption_data is not None and full_path != "/":
                    analysis["encrypted_files"].append(full_path)
                    self._extract_encryption_info(
                        encryption_data, analysis, ns_manifest
                    )

            return analysis

        except Exception:
            return {}

    def _extract_encryption_info(
        self, encryption_data, analysis: Dict, ns_manifest: str
    ):
        """Extract encryption details from encryption-data element."""
        # Algorithm
        algorithm = encryption_data.find(f"{{{ns_manifest}}}algorithm")
        if algorithm is not None:
            algo_name = algorithm.get(f"{{{ns_manifest}}}algorithm-name")
            analysis["encryption_algorithms"].append(algo_name)

        # Key derivation
        key_derivation = encryption_data.find(f"{{{ns_manifest}}}key-derivation")
        if key_derivation is not None:
            kdf_name = key_derivation.get(f"{{{ns_manifest}}}key-derivation-name")
            analysis["key_derivation_methods"].append(kdf_name)

        # Checksum
        checksum_type = encryption_data.get(f"{{{ns_manifest}}}checksum-type")
        if checksum_type:
            analysis["checksum_types"].append(checksum_type)

    def detect_encryption_format(self, manifest_analysis: Dict) -> str:
        """Determine the encryption format and origin."""

        # LibreOffice modern format indicators
        if manifest_analysis.get("has_encrypted_package"):
            algorithms = manifest_analysis.get("encryption_algorithms", [])
            key_derivations = manifest_analysis.get("key_derivation_methods", [])

            # Check for LibreOffice-specific algorithms
            if "http://www.w3.org/2009/xmlenc11#aes256-gcm" in algorithms:
                return "libreoffice_modern"
            if (
                "urn:org:documentfoundation:names:experimental:office:manifest:argon2id"
                in key_derivations
            ):
                return "libreoffice_modern"

            # Check for LibreOffice namespaces
            if manifest_analysis.get("libreoffice_namespaces"):
                return "libreoffice_modern"

            return "libreoffice_modern"

        # Check for individual file encryption (could be either)
        encrypted_files = manifest_analysis.get("encrypted_files", [])
        if encrypted_files:
            algorithms = set(manifest_analysis.get("encryption_algorithms", []))
            key_derivations = set(manifest_analysis.get("key_derivation_methods", []))
            checksums = set(manifest_analysis.get("checksum_types", []))

            # Apache OpenOffice specific indicators
            if algorithms == {"Blowfish CFB"} and key_derivations == {"PBKDF2"}:
                if "SHA1/1K" in checksums:
                    return "apache_openoffice"
                return "apache_openoffice"

            # LibreOffice legacy format
            if "http://www.w3.org/2001/04/xmlenc#aes256-cbc" in algorithms:
                return "libreoffice_legacy"

            # Mixed algorithms suggest LibreOffice
            if len(algorithms) > 1:
                return "libreoffice_legacy"

            # Default to AOO for classic Blowfish+PBKDF2
            if "Blowfish CFB" in algorithms and "PBKDF2" in key_derivations:
                return "likely_apache_openoffice"

        return "unknown"

    def analyze_file_structure(self, zf: zipfile.ZipFile) -> Dict[str, any]:
        """Analyze file structure for origin indicators."""
        analysis = {
            "file_list": zf.namelist(),
            "has_libreoffice_specific": False,
            "has_configurations2": False,
            "has_manifest_rdf": False,
            "mimetype": None,
            "has_thumbnails": False,
            "libreoffice_specific_files": [],
            "aoo_specific_files": [],
        }

        file_list = zf.namelist()

        # Check mimetype
        if "mimetype" in file_list:
            try:
                analysis["mimetype"] = zf.read("mimetype").decode("utf-8").strip()
            except Exception:
                pass

        # Check for Configurations2 directory
        config_files = [f for f in file_list if f.startswith("Configurations2/")]
        if config_files:
            analysis["has_configurations2"] = True

        # Check for Thumbnails (LibreOffice indicator)
        thumb_files = [f for f in file_list if f.startswith("Thumbnails/")]
        if thumb_files:
            analysis["has_thumbnails"] = True

        # Check for manifest.rdf
        if "manifest.rdf" in file_list:
            analysis["has_manifest_rdf"] = True

        return analysis

    def analyze_version_info(self, zf: zipfile.ZipFile) -> Dict[str, any]:
        """Analyze version and generator information."""
        analysis = {}

        # Try to get generator from meta.xml
        if "meta.xml" in zf.namelist():
            try:
                meta_content = zf.read("meta.xml").decode("utf-8")
                # Extract generator info with better regex
                import re

                generator_match = re.search(
                    r"<meta:generator[^>]*>([^<]+)</meta:generator>",
                    meta_content,
                    re.IGNORECASE,
                )
                if generator_match:
                    generator = generator_match.group(1).strip()
                    analysis["generator"] = generator
            except Exception:
                pass

        return analysis

    def detect_origin(self, file_path: str) -> OpenOfficeOrigin:
        """
        Detect the origin of an ODF file.

        Args:
            file_path: Path to the ODF file

        Returns:
            OpenOfficeOrigin: UNKNOWN, APACHE_OPEN_OFFICE, or LIBREOFFICE

        Raises:
            FileNotFoundError: If the file does not exist
        """
        import os

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                # Start with UNKNOWN as the default
                origin = OpenOfficeOrigin.UNKNOWN

                # Basic validation - if not a valid ODF file, return UNKNOWN
                if "mimetype" not in zf.namelist():
                    return OpenOfficeOrigin.UNKNOWN

                # Analyze manifest structure
                manifest_analysis = self.analyze_manifest_structure(zf)

                # Detect encryption format
                encryption_format = self.detect_encryption_format(manifest_analysis)

                # Analyze version info
                version_analysis = self.analyze_version_info(zf)

                # Determine final origin based on strongest indicators

                # High confidence indicators
                if encryption_format == "libreoffice_modern":
                    return OpenOfficeOrigin.LIBREOFFICE
                elif encryption_format == "apache_openoffice":
                    return OpenOfficeOrigin.APACHE_OPEN_OFFICE
                elif "generator" in version_analysis:
                    if "LibreOffice" in version_analysis["generator"]:
                        return OpenOfficeOrigin.LIBREOFFICE
                    elif "OpenOffice" in version_analysis["generator"]:
                        return OpenOfficeOrigin.APACHE_OPEN_OFFICE

                # Medium confidence based on encryption patterns
                elif encryption_format == "libreoffice_legacy":
                    return OpenOfficeOrigin.LIBREOFFICE
                elif encryption_format == "likely_apache_openoffice":
                    return OpenOfficeOrigin.APACHE_OPEN_OFFICE
                elif encryption_format == "unknown":
                    # No encryption detected, try other indicators
                    pass

                # If no clear evidence found, return UNKNOWN
                return origin

        except zipfile.BadZipFile:
            return OpenOfficeOrigin.UNKNOWN  # Invalid file
        except Exception:
            return OpenOfficeOrigin.UNKNOWN  # Other errors
