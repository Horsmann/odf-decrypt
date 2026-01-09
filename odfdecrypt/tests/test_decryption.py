import io
import logging
import unittest

import sharepoint2text

from odfdecrypt.decryption.apache_odf_decryptor import AOODecryptor
from odfdecrypt.decryption.libre_office_odf_decryptor import LibreOfficeDecryptor

tc = unittest.TestCase()

logger = logging.getLogger()


def test_libre_office_decrypt():
    decryptor = LibreOfficeDecryptor()

    fl: io.BytesIO = decryptor.decrypt(
        "odfdecrypt/tests/resources/password_protected/libre_office_sample_pw_hello.odt",
        "hello",
    )

    obj = next(sharepoint2text.read_odt(fl))
    tc.assertEqual("Hey ho :)", obj.get_full_text())

    fl: io.BytesIO = decryptor.decrypt(
        "odfdecrypt/tests/resources/password_protected/libre_office_spreadsheet_pw_hello.ods",
        "hello",
    )

    obj = next(sharepoint2text.read_ods(fl))
    tc.assertEqual("Sheet1\nHello!", obj.get_full_text())

    fl: io.BytesIO = decryptor.decrypt(
        "odfdecrypt/tests/resources/password_protected/libre_office_presentation_pw_hello.odp",
        "hello",
    )

    obj = next(sharepoint2text.read_odp(fl))
    tc.assertEqual("XYZ", obj.get_full_text())

    fl: io.BytesIO = decryptor.decrypt(
        "odfdecrypt/tests/resources/password_protected/libre_office_drawing_pw_hello.odg",
        "hello",
    )

    obj = next(sharepoint2text.read_odg(fl))
    tc.assertEqual("A text box", obj.get_full_text())

    fl: io.BytesIO = decryptor.decrypt(
        "odfdecrypt/tests/resources/password_protected/libre_office_formular_pw_hello.odf",
        "hello",
    )

    obj = next(sharepoint2text.read_odf(fl))
    tc.assertEqual("{5} over {6}", obj.get_full_text())


def test_apache_office_decrypt():
    decryptor = AOODecryptor()

    fl: io.BytesIO = decryptor.decrypt(
        "odfdecrypt/tests/resources/password_protected/aoo_document_pw_hello.odt",
        "hello",
    )

    obj = next(sharepoint2text.read_odt(fl))
    tc.assertEqual("Mission accomplished", obj.get_full_text())

    fl: io.BytesIO = decryptor.decrypt(
        "odfdecrypt/tests/resources/password_protected/aoo_presentation_pw_hello.odp",
        "hello",
    )

    obj = next(sharepoint2text.read_odp(fl))
    tc.assertEqual("Fire!", obj.get_full_text())
