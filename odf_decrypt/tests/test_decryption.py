import io
import logging
import unittest

import sharepoint2text

from odf_decrypt.apache_odf_decryptor import AOODecryptor
from odf_decrypt.libre_office_odf_decryptor import LibreOfficeDecryptor

tc = unittest.TestCase()

logger = logging.getLogger()


def test_libre_office_decrypt():
    decryptor = LibreOfficeDecryptor()

    fl: io.BytesIO = decryptor.decrypt(
        "odf_decrypt/tests/resources/password_protected/libreoffice_sample_pw_hello.odt",
        "hello",
    )

    obj = next(sharepoint2text.read_odt(fl))
    tc.assertEqual("Hey ho :)", obj.get_full_text())


def test_apache_office_decrypt():
    decryptor = AOODecryptor()

    fl: io.BytesIO = decryptor.decrypt_odf_file_to_bytesio(
        "odf_decrypt/tests/resources/password_protected/aoo_document_pw_hello.odt",
        "hello",
    )

    obj = next(sharepoint2text.read_odt(fl))
    tc.assertEqual("Mission accomplished", obj.get_full_text())

    fl: io.BytesIO = decryptor.decrypt_odf_file_to_bytesio(
        "odf_decrypt/tests/resources/password_protected/aoo_presentation_pw_hello.odp",
        "hello",
    )

    obj = next(sharepoint2text.read_odp(fl))
    tc.assertEqual("Fire!", obj.get_full_text())
