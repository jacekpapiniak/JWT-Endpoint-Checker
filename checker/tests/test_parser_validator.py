import pytest
from checker.src.parser_validator import get_token_type, validate_arguments


# Test cases for get_token_type function
# This pytest.mark.parametrize allows is an equivalent to C# [TestCase] attribute
# And it allows to run multiple test cases with different parameters for the same test function.
# Instead of writing separate tests for each case.
@pytest.mark.parametrize("url_token_value, expected", [
    ("http://example.com/api/login", "url"),
    ("https://example.com/api/login", "url"),
])

def test_get_token_type_when_given_url_return_url(url_token_value, expected):
    actual = get_token_type(url_token_value)
    assert actual == expected

# This test checks if the get_token_type returns "file" when given a valid file path.
# An awsome feature of pytest is usage of fixtures such as temp_path, this allows to create
# temporary files and directories for testing purposes, and they are automatically cleaned up after the test.
# This way we can keep structure clean and not littered by test files.
# For list of available fixtures run pytest --fixtures command in terminal.
def test_get_token_type_when_given_file_path_return_file(tmp_path):
    # Create a temporary file for testing
    test_file_path = tmp_path / "test_token.txt"
    test_file_path.write_text("This is a test token file.")

    actual = get_token_type(str(test_file_path))

    assert actual == "file"

#This test checks if "string" returned when path provided but file does not exist.
def test_get_token_type_when_given_non_existent_file_path_return_string(tmp_path):
    # Create a temporary file path for testing, but do not create the file itself
    non_existent_file_path = tmp_path / "non_existent_token.txt"

    actual = get_token_type(str(non_existent_file_path))

    assert actual == "string"

# This test checks if the get_token_type returns "string" when given a raw string that is neither a valid URL nor a valid file path.
def test_get_token_type_when_given_raw_string_return_string():
    raw_token_value = "my_raw_token_value"

    actual = get_token_type(raw_token_value)

    assert actual == "string"