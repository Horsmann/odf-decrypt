import io
import unittest

import sharepoint2text

from odfdecrypt.api import decrypt, detect_origin
from odfdecrypt.exceptions import IncorrectPasswordError
from odfdecrypt.odf_origin_detector import OpenOfficeOrigin

tc = unittest.TestCase()


def test_detect_origin_wrapper_libreoffice():
    origin = detect_origin(
        "odfdecrypt/tests/resources/password_protected/libre_office_sample_pw_hello.odt"
    )
    tc.assertEqual(OpenOfficeOrigin.LIBREOFFICE, origin)


def test_detect_origin_wrapper_apache_openoffice():
    origin = detect_origin(
        "odfdecrypt/tests/resources/password_protected/aoo_document_pw_hello.odt"
    )
    tc.assertEqual(OpenOfficeOrigin.APACHE_OPEN_OFFICE, origin)


def test_decrypt_auto_libreoffice_success():
    fl = decrypt(
        "odfdecrypt/tests/resources/password_protected/libre_office_sample_pw_hello.odt",
        "hello",
    )
    obj = next(sharepoint2text.read_odt(fl))
    tc.assertEqual("Hey ho :)", obj.get_full_text())


def test_decrypt_auto_apache_openoffice_success():
    fl = decrypt(
        "odfdecrypt/tests/resources/password_protected/aoo_document_pw_hello.odt",
        "hello",
    )
    obj = next(sharepoint2text.read_odt(fl))
    tc.assertEqual("Mission accomplished", obj.get_full_text())


def test_decrypt_auto_wrong_password_raises():
    with tc.assertRaises(IncorrectPasswordError):
        decrypt(
            "odfdecrypt/tests/resources/password_protected/libre_office_sample_pw_hello.odt",
            "wrong_password",
        )


def test_decrypt_auto_bytesio_fallback_to_aoo():
    path = "odfdecrypt/tests/resources/password_protected/aoo_document_pw_hello.odt"
    with open(path, "rb") as f:
        buf = io.BytesIO(f.read())
    fl = decrypt(buf, "hello")
    obj = next(sharepoint2text.read_odt(fl))
    tc.assertEqual("Mission accomplished", obj.get_full_text())
