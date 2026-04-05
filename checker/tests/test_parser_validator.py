import pytest

from checker.src.cli import build_cli
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
def test_get_token_type_when_given_file_path_consist_onl_of_txt_file_name_return_file():
    actual = get_token_type("token.txt")

    assert actual == "file"

# This test checks if the get_token_type returns "string" when given a raw string that is neither a valid URL nor a valid file path.
def test_get_token_type_when_given_raw_string_return_string():
    raw_token_value = "my_raw_token_value"

    actual = get_token_type(raw_token_value)

    assert actual == "string"

# This section tests validate_arguments
# The parser.error() raises a SystemExit exception, so we need to catch that in our tests to check if the correct error message is produced.
def test_validate_arguments_when_no_arguments_provided_should_raise_system_exit_exception():
    parser = build_cli()
    args = parser.parse_args([]) # No arguments provided

    # with pytest.raises() we can check if the code inside the block raises in this case SystemExit.
    # C# equivalent would be Assert.Throws<SystemExit>(() => validate_arguments(parser, args));
    with pytest.raises(SystemExit):
        validate_arguments(parser, args)

def test_validate_arguments_when_api_flags_mixed_with_analysis_parameters_should_raise_system_exit_exception():
    parser = build_cli()
    args = parser.parse_args(["-s", "-t", "http://example.com/api/login"]) # Mixing API start flag with token parameter

    with pytest.raises(SystemExit):
        validate_arguments(parser, args)

def test_validate_arguments_when_credentials_provided_without_token_flag_should_raise_system_exit_exception():
    parser = build_cli()
    args = parser.parse_args(["-c", "email,password"]) # Providing credentials without token endpoint

    with pytest.raises(SystemExit):
        validate_arguments(parser, args)

def test_validate_arguments_when_target_test_endpoint_provided_without_token_flag_should_raise_system_exit_exception():
    parser = build_cli()
    args = parser.parse_args(["-e", "http://example.com/api/test"]) # Providing test endpoint without token endpoint

    with pytest.raises(SystemExit):
        validate_arguments(parser, args)

def test_validate_arguments_when_valid_token_flag_is_url_provided_without_credentials_should_raise_exception():
    parser = build_cli()
    args = parser.parse_args(["-t", "http://example.com/api/login"]) # Providing valid token endpoint without credentials

    with pytest.raises(SystemExit):
        validate_arguments(parser, args)

def test_validate_arguments_when_token_flag_is_file_path_that_does_not_exist_should_raise_exception():
    parser = build_cli()
    non_existent_file_path = "C:/files/non_existent_token.txt"
    args = parser.parse_args(["-t", str(non_existent_file_path)]) # Providing non-existent file path as token

    with pytest.raises(SystemExit):
        validate_arguments(parser, args)

def test_validate_arguments_when_valid_token_flag_is_file_path_provided_without_credentials_should_raise_exception(tmp_path):
    parser = build_cli()
    # Create a temporary file for testing
    test_file_path = tmp_path / "test_token.txt" # valid path
    test_file_path.write_text("http://example.com/api/login") # valid content that looks like URL

    args = parser.parse_args(["-t", str(test_file_path)]) # Providing valid file path as token without credentials

    with pytest.raises(SystemExit):
        validate_arguments(parser, args)

def test_validate_arguments_when_valid_credentials_flag_is_file_path_provided_without_token_endpoint_should_raise_exception(tmp_path):
    parser = build_cli()
    # Create a temporary file for testing
    test_file_path = tmp_path / "test_credentials.txt" # valid path
    test_file_path.write_text("test@test.co.uk,Password1234") # valid content that looks like URL

    args = parser.parse_args(["-c", str(test_file_path)]) # Providing valid file path as token without credentials

    with pytest.raises(SystemExit):
        validate_arguments(parser, args)


def test_validate_arguments_when_valid_token_flag_is_jwt_token_should_not_raise_exception():
    parser = build_cli()
    jwt_token_value = "eyJhbGciOiJIUzI1Ni.adata.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    args = parser.parse_args(["-t", jwt_token_value]) # Providing valid JWT token

    # If no exception is raised, the test will pass. If an exception is raised, the test will fail.
    try:
        validate_arguments(parser, args)
    except SystemExit:
        pytest.fail("validate_arguments raised SystemExit unexpectedly!")

def test_validate_arguments_when_valid_token_flag_is_url_and_credentials_provided_should_not_raise_exception():
    parser = build_cli()
    args = parser.parse_args(["-t", "http://example.com/api/login", "-c", "test@test.co.uk, Password1234!"]) # Providing valid JWT token endpoint and credentials

    # If no exception is raised, the test will pass. If an exception is raised, the test will fail.
    try:
        validate_arguments(parser, args)
    except SystemExit:
        pytest.fail("validate_arguments raised SystemExit unexpectedly!")

def test_validate_arguments_when_valid_token_flag_is_file_with_url_and_credentials_provided_should_not_raise_exception(tmp_path):
    parser = build_cli()
    test_file_path = tmp_path / "test_token.txt" # valid path
    test_file_path.write_text("http://example.com/api/login") # valid content that looks like URL
    args = parser.parse_args(["-t", str(test_file_path), "-c", "test@test.co.uk, Password1234!"]) # Providing valid JWT token endpoint and credentials

    # If no exception is raised, the test will pass. If an exception is raised, the test will fail.
    try:
        validate_arguments(parser, args)
    except SystemExit:
        pytest.fail("validate_arguments raised SystemExit unexpectedly!")

def test_validate_arguments_when_valid_command_with_all_flags_provided_should_not_raise_exception(tmp_path):
    parser = build_cli()
    test_file_path = tmp_path / "test_token.txt" # valid path
    test_file_path.write_text("http://example.com/api/login") # valid content that looks like URL
    args = parser.parse_args(["-t", str(test_file_path), "-c", "test@test.co.uk, Password1234!", "-e", "http://example.com/api/profile"]) # Providing valid JWT token endpoint and credentials

    # If no exception is raised, the test will pass. If an exception is raised, the test will fail.
    try:
        validate_arguments(parser, args)
    except SystemExit:
        pytest.fail("validate_arguments raised SystemExit unexpectedly!")