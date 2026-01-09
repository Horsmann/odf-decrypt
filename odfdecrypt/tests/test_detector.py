import logging
import tempfile
import unittest

from odfdecrypt.odf_origin_detector import ODFOriginDetector, OpenOfficeOrigin

logger = logging.getLogger(__name__)

tc = unittest.TestCase()


def test_apache_office_detector():
    detector = ODFOriginDetector()

    origin = detector.detect_origin(
        "odfdecrypt/tests/resources/password_protected/aoo_document_pw_hello.odt"
    )
    tc.assertEqual(OpenOfficeOrigin.APACHE_OPEN_OFFICE, origin)

    origin = detector.detect_origin("odfdecrypt/tests/resources/plain/aoo_drawing.odg")
    tc.assertEqual(OpenOfficeOrigin.APACHE_OPEN_OFFICE, origin)

    origin = detector.detect_origin("odfdecrypt/tests/resources/plain/aoo_formula.odf")
    tc.assertEqual(OpenOfficeOrigin.APACHE_OPEN_OFFICE, origin)

    origin = detector.detect_origin(
        "odfdecrypt/tests/resources/plain/aoo_presentation.odp"
    )
    tc.assertEqual(OpenOfficeOrigin.APACHE_OPEN_OFFICE, origin)

    origin = detector.detect_origin(
        "odfdecrypt/tests/resources/plain/aoo_spreadsheet.ods"
    )
    tc.assertEqual(OpenOfficeOrigin.APACHE_OPEN_OFFICE, origin)


def test_libre_office_detector():
    detector = ODFOriginDetector()

    origin = detector.detect_origin(
        "odfdecrypt/tests/resources/password_protected/libre_office_sample_pw_hello.odt"
    )
    tc.assertEqual(OpenOfficeOrigin.LIBREOFFICE, origin)

    origin = detector.detect_origin(
        "odfdecrypt/tests/resources/plain/libre_office_presentation.odp"
    )
    tc.assertEqual(OpenOfficeOrigin.LIBREOFFICE, origin)

    origin = detector.detect_origin(
        "odfdecrypt/tests/resources/plain/libre_office_spreadsheet.ods"
    )
    tc.assertEqual(OpenOfficeOrigin.LIBREOFFICE, origin)

    origin = detector.detect_origin(
        "odfdecrypt/tests/resources/plain/libre_office_draw.odg"
    )
    tc.assertEqual(OpenOfficeOrigin.LIBREOFFICE, origin)


def test_unknown_origin_detector():
    detector = ODFOriginDetector()

    # Test with nonexistent file (should raise FileNotFoundError)
    with tc.assertRaises(FileNotFoundError):
        detector.detect_origin("nonexistent_file.odt")

    # Test with invalid file (should return UNKNOWN)
    with tempfile.NamedTemporaryFile(suffix=".odt", delete=False) as tmp:
        tmp.write(b"This is not a valid ZIP file")
        tmp_path = tmp.name

    import os

    try:
        origin = detector.detect_origin(tmp_path)
        tc.assertEqual(OpenOfficeOrigin.UNKNOWN, origin)
    finally:
        os.unlink(tmp_path)
