"""Tests for the CLI module."""

import os
import tempfile
import unittest
import zipfile

from odfdecrypt.cli import (
    get_default_output_path,
    is_encrypted,
    main,
)
from odfdecrypt.exceptions import IncorrectPasswordError

tc = unittest.TestCase()


class TestIsEncrypted:
    """Tests for the is_encrypted function."""

    def test_encrypted_libreoffice_file(self):
        """Test that encrypted LibreOffice files are detected."""
        test_file = os.path.join(
            os.path.dirname(__file__),
            "resources/password_protected/libre_office_sample_pw_hello.odt",
        )
        tc.assertTrue(is_encrypted(test_file))

    def test_encrypted_aoo_file(self):
        """Test that encrypted Apache OpenOffice files are detected."""
        test_file = os.path.join(
            os.path.dirname(__file__),
            "resources/password_protected/aoo_document_pw_hello.odt",
        )
        tc.assertTrue(is_encrypted(test_file))

    def test_plain_file_not_encrypted(self):
        """Test that plain files are not detected as encrypted."""
        test_file = os.path.join(
            os.path.dirname(__file__),
            "resources/plain/aoo_spreadsheet.ods",
        )
        tc.assertFalse(is_encrypted(test_file))

    def test_plain_libreoffice_file(self):
        """Test that plain LibreOffice files are not detected as encrypted."""
        test_file = os.path.join(
            os.path.dirname(__file__),
            "resources/plain/libre_office_spreadsheet.ods",
        )
        tc.assertFalse(is_encrypted(test_file))

    def test_nonexistent_file(self):
        """Test that nonexistent files return False."""
        tc.assertFalse(is_encrypted("/nonexistent/file.odt"))

    def test_invalid_zip_file(self):
        """Test that invalid zip files return False."""
        with tempfile.NamedTemporaryFile(suffix=".odt", delete=False) as f:
            f.write(b"not a zip file")
            temp_path = f.name

        try:
            tc.assertFalse(is_encrypted(temp_path))
        finally:
            os.unlink(temp_path)


class TestGetDefaultOutputPath:
    """Tests for the get_default_output_path function."""

    def test_simple_path(self):
        """Test default output path generation."""
        tc.assertEqual(
            get_default_output_path("document.odt"), "document_decrypted.odt"
        )

    def test_path_with_directory(self):
        """Test output path with directory."""
        tc.assertEqual(
            get_default_output_path("/path/to/document.odt"),
            "/path/to/document_decrypted.odt",
        )

    def test_different_extensions(self):
        """Test with different ODF extensions."""
        tc.assertEqual(get_default_output_path("sheet.ods"), "sheet_decrypted.ods")
        tc.assertEqual(get_default_output_path("slides.odp"), "slides_decrypted.odp")
        tc.assertEqual(get_default_output_path("drawing.odg"), "drawing_decrypted.odg")

    def test_no_extension(self):
        """Test file without extension."""
        tc.assertEqual(get_default_output_path("document"), "document_decrypted")


class TestMainCLI:
    """Tests for the main CLI function."""

    def test_missing_file_argument(self):
        """Test that missing --file argument causes error."""
        with tc.assertRaises(SystemExit) as cm:
            main(["--password", "hello"])
        tc.assertEqual(cm.exception.code, 2)  # argparse error code

    def test_missing_password_argument(self):
        """Test that missing --password argument causes error."""
        with tc.assertRaises(SystemExit) as cm:
            main(["--file", "test.odt"])
        tc.assertEqual(cm.exception.code, 2)  # argparse error code

    def test_nonexistent_file(self, capsys):
        """Test error when file doesn't exist."""
        result = main(["--file", "/nonexistent/file.odt", "--password", "hello"])
        tc.assertEqual(result, 1)
        captured = capsys.readouterr()
        tc.assertIn("File not found", captured.err)

    def test_decrypt_libreoffice_file(self):
        """Test decrypting a LibreOffice encrypted file."""
        test_file = os.path.join(
            os.path.dirname(__file__),
            "resources/password_protected/libre_office_sample_pw_hello.odt",
        )

        with tempfile.NamedTemporaryFile(suffix=".odt", delete=False) as f:
            output_path = f.name

        try:
            result = main(
                ["--file", test_file, "--password", "hello", "--output", output_path]
            )
            tc.assertEqual(result, 0)
            tc.assertTrue(os.path.exists(output_path))

            # Verify the output is a valid ODF file
            with zipfile.ZipFile(output_path, "r") as zf:
                tc.assertIn("mimetype", zf.namelist())
                tc.assertIn("content.xml", zf.namelist())
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)

    def test_decrypt_aoo_file(self):
        """Test decrypting an Apache OpenOffice encrypted file."""
        test_file = os.path.join(
            os.path.dirname(__file__),
            "resources/password_protected/aoo_document_pw_hello.odt",
        )

        with tempfile.NamedTemporaryFile(suffix=".odt", delete=False) as f:
            output_path = f.name

        try:
            result = main(
                ["--file", test_file, "--password", "hello", "--output", output_path]
            )
            tc.assertEqual(result, 0)
            tc.assertTrue(os.path.exists(output_path))

            # Verify the output is a valid ODF file
            with zipfile.ZipFile(output_path, "r") as zf:
                tc.assertIn("mimetype", zf.namelist())
                tc.assertIn("content.xml", zf.namelist())
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)

    def test_copy_unencrypted_file(self, capsys):
        """Test that unencrypted files are just copied."""
        test_file = os.path.join(
            os.path.dirname(__file__),
            "resources/plain/aoo_spreadsheet.ods",
        )

        with tempfile.NamedTemporaryFile(suffix=".ods", delete=False) as f:
            output_path = f.name

        try:
            result = main(
                ["--file", test_file, "--password", "hello", "--output", output_path]
            )
            tc.assertEqual(result, 0)
            tc.assertTrue(os.path.exists(output_path))

            captured = capsys.readouterr()
            tc.assertIn("not encrypted", captured.out)
            tc.assertIn("Copied to", captured.out)

            # Verify the output matches the input
            with open(test_file, "rb") as f1, open(output_path, "rb") as f2:
                tc.assertEqual(f1.read(), f2.read())
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)

    def test_default_output_path(self):
        """Test that default output path is used when --output not specified."""
        test_file = os.path.join(
            os.path.dirname(__file__),
            "resources/password_protected/libre_office_sample_pw_hello.odt",
        )
        expected_output = get_default_output_path(test_file)

        try:
            result = main(["--file", test_file, "--password", "hello"])
            tc.assertEqual(result, 0)
            tc.assertTrue(os.path.exists(expected_output))

            # Verify the output is a valid ODF file
            with zipfile.ZipFile(expected_output, "r") as zf:
                tc.assertIn("mimetype", zf.namelist())
        finally:
            if os.path.exists(expected_output):
                os.unlink(expected_output)

    def test_wrong_password(self):
        """Test that wrong password causes decryption failure."""
        test_file = os.path.join(
            os.path.dirname(__file__),
            "resources/password_protected/libre_office_sample_pw_hello.odt",
        )

        with tempfile.NamedTemporaryFile(suffix=".odt", delete=False) as f:
            output_path = f.name

        try:
            with tc.assertRaises(IncorrectPasswordError):
                main(
                    [
                        "--file",
                        test_file,
                        "--password",
                        "wrong_password",
                        "--output",
                        output_path,
                    ]
                )
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)

    def test_short_options(self):
        """Test that short options -f, -p, -o work."""
        test_file = os.path.join(
            os.path.dirname(__file__),
            "resources/password_protected/aoo_document_pw_hello.odt",
        )

        with tempfile.NamedTemporaryFile(suffix=".odt", delete=False) as f:
            output_path = f.name

        try:
            result = main(["-f", test_file, "-p", "hello", "-o", output_path])
            tc.assertEqual(result, 0)
            tc.assertTrue(os.path.exists(output_path))
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)

    def test_create_output_subdirectory(self):
        """Test that output subdirectories are created if they don't exist."""
        test_file = os.path.join(
            os.path.dirname(__file__),
            "resources/password_protected/libre_office_sample_pw_hello.odt",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a nested output path that doesn't exist yet
            output_path = os.path.join(temp_dir, "subdir1", "subdir2", "decrypted.odt")

            # Ensure the subdirectories don't exist initially
            tc.assertFalse(os.path.exists(os.path.dirname(output_path)))

            try:
                result = main(
                    [
                        "--file",
                        test_file,
                        "--password",
                        "hello",
                        "--output",
                        output_path,
                    ]
                )
                tc.assertEqual(result, 0)
                tc.assertTrue(os.path.exists(output_path))

                # Verify the subdirectories were created
                tc.assertTrue(os.path.exists(os.path.dirname(output_path)))

                # Verify the output is a valid ODF file
                with zipfile.ZipFile(output_path, "r") as zf:
                    tc.assertIn("mimetype", zf.namelist())
                    tc.assertIn("content.xml", zf.namelist())
            finally:
                # Cleanup will be handled by TemporaryDirectory context manager
                pass

    def test_create_output_subdirectory_for_copy(self):
        """Test that output subdirectories are created for unencrypted files too."""
        test_file = os.path.join(
            os.path.dirname(__file__),
            "resources/plain/aoo_spreadsheet.ods",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a nested output path that doesn't exist yet
            output_path = os.path.join(temp_dir, "output", "subdir", "copied.ods")

            # Ensure the subdirectories don't exist initially
            tc.assertFalse(os.path.exists(os.path.dirname(output_path)))

            try:
                result = main(
                    [
                        "--file",
                        test_file,
                        "--password",
                        "hello",
                        "--output",
                        output_path,
                    ]
                )
                tc.assertEqual(result, 0)
                tc.assertTrue(os.path.exists(output_path))

                # Verify the subdirectories were created
                tc.assertTrue(os.path.exists(os.path.dirname(output_path)))

                # Verify the output matches the input (copied file)
                with open(test_file, "rb") as f1, open(output_path, "rb") as f2:
                    tc.assertEqual(f1.read(), f2.read())
            finally:
                # Cleanup will be handled by TemporaryDirectory context manager
                pass
