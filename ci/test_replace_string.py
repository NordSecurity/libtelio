import os
import tempfile
import unittest
from replace_string import replace_string_in_file


class TestReplaceStringInFile(unittest.TestCase):
    def test_replace_string(self):
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_file:
            temp_file.write("original testing string")

        # Test replacing the string
        original_str = "original"
        new_str = "lanigiro"
        replace_string_in_file(temp_file.name, original_str, new_str)

        # Verify the contents of the file after replacement
        with open(temp_file.name, "r", encoding="utf-8") as file:
            content = file.read()
            self.assertEqual(content, "lanigiro testing string")

        # Clean up the temporary file
        os.unlink(temp_file.name)

    def test_original_string_not_found(self):
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_file:
            temp_file.write("some content")

        # Test when the original string is not found
        original_str = "original"
        new_str = "new_string"
        with self.assertRaises(ValueError):
            replace_string_in_file(temp_file.name, original_str, new_str)

        # Clean up the temporary file
        os.unlink(temp_file.name)

    def test_multiple_original_strings(self):
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_file:
            temp_file.write("original original original")

        # Test when there are multiple original strings
        original_str = "original"
        new_str = "new_string"
        with self.assertRaises(ValueError):
            replace_string_in_file(temp_file.name, original_str, new_str)

        # Clean up the temporary file
        os.unlink(temp_file.name)

    def test_new_string_longer(self):
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_file:
            temp_file.write("original")

        # Test when the new string is longer
        original_str = "original"
        new_str = "new_string_longer_than_original"
        with self.assertRaises(ValueError):
            replace_string_in_file(temp_file.name, original_str, new_str)

        # Clean up the temporary file
        os.unlink(temp_file.name)

    def test_new_string_shorter(self):
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_file:
            temp_file.write("original")

        # Test when the new string is longer
        original_str = "original"
        new_str = "new"
        replace_string_in_file(temp_file.name, original_str, new_str)

        # Verify the contents of the file after replacement
        with open(temp_file.name, "r", encoding="utf-8") as file:
            content = file.read()
            self.assertEqual(
                content,
                "new" + "\0" * (len(original_str) - len(new_str)),
            )

        # Clean up the temporary file
        os.unlink(temp_file.name)


if __name__ == "__main__":
    unittest.main()
