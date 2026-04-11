from http.client import responses

import pytest
import responses # Import responses for mocking HTTP requests in tests
from checker.src.cli.cli import build_cli
from checker.src.jwt.token_loader import load_token, load_token_from_file, load_token_from_url
from checker.src.validators.parser_validator import get_token_type, validate_arguments

# Test cases for token_loader.py

test_jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2YWxpZEB1c2VyLnRlc3QuY28udWsiLCJlbWFpbCI6InZhbGlkQHVzZXIudGVzdC5jby51ayIsImp0aSI6IjA3Nzk5YWNjLTNlYmYtNGFlOS1iOWRkLTNjN2VjODA1NTI3MyIsImV4cCI6MTc3NTkwNzcxMiwiaXNzIjoiSnd0VGVzdEFwaSIsImF1ZCI6Ikp3dFRlc3RBcGlVc2VycyJ9.LKodA7Hw5W32FcPzrTDGNXPQpLHVMe_hNieXBwI8ZD4"

def test_load_token_from_string_when_valid_jwt_token_should_return_token_value():
    actual = load_token(test_jwt_token, None, None)

    assert actual == test_jwt_token

def test_load_token_from_file_when_valid_file_path_and_content_is_jwt_token_should_return_file_content(tmp_path):
    # Create a temporary file for testing
    test_file_path = tmp_path / "test_token.txt"
    test_file_path.write_text(test_jwt_token)

    # Call the function to load the token from the file
    actual = load_token(str(test_file_path), None, None)

    assert actual == test_jwt_token, "The content loaded from the file should match the expected JWT token value."

def test_load_token_from_file_when_file_does_not_exist_should_raise_exception():
    # Create a temporary file path that does not exist
    test_file_path = "C:/non_existent_file.txt"

    with pytest.raises(ValueError) as exc_info:
        load_token(str(test_file_path), None, None)

    assert str(exc_info.value) == f"The specified token file does not exist: {test_file_path}"


# responses.activate is a decorator that allows us to mock HTTP responses for testing purposes.
# It is part of the responses library, which is commonly used in Python for mocking HTTP requests in tests.
# By using this decorator, we can simulate different scenarios when loading a token from a URL without making actual HTTP requests to the specified URL.
# Decorator pattern is used to modify the behaviour of the load_token_from_file function during testing,
# Allowing us to control the responses from the URL and test how the function handles those responses.
@responses.activate # No real HTTP requests will be made within this test function, and we can define mock responses for specific URLs.
def test_load_token_from_file_when_valid_file_path_and_content_is_url_should_return_token_from_POST_response(tmp_path):
    # Create a temporary file for testing
    test_file_path = tmp_path / "test_token.txt"
    url = "http://superhacky.co.uk:5000/api/login"
    test_file_path.write_text(url)

    # Mock the POST response
    responses.add(responses.POST, url, json={"jwtToken": test_jwt_token}, status=200)

    # Call the function to load the token from the file
    actual = load_token(str(test_file_path), "email", "password")
    print(f"Actual token loaded from file: {actual}")
    assert actual == test_jwt_token, "The content loaded from the file should match the expected JWT token value."

def test_load_token_from_url_when_invalid_url_should_throw():
    url = "Invalid Url"
    with pytest.raises(ValueError) as exc_info:
        load_token_from_url(url, None, None)

    assert str(exc_info.value) == f"The specified token URL is not valid: {url}"

def test_load_token_from_url_when_email_not_provided_should_throw():
    url = "http://superhacky.co.uk:5000/api/login"
    with pytest.raises(ValueError) as exc_info:
        load_token_from_url(url, None, "Password1234")

    assert str(exc_info.value) == "Email cannot be empty. Please provide a valid email using the -c or --credentials flag in the format email,password."

def test_load_token_from_url_when_password_not_provided_should_throw():
    url = "http://superhacky.co.uk:5000/api/login"
    with pytest.raises(ValueError) as exc_info:
        load_token_from_url(url, "test@email.com", None)

    assert str(exc_info.value) == "Password cannot be empty. Please provide a valid password using the -c or --credentials flag in the format email,password."