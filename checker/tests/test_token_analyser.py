import pytest
import base64
import json
from checker.src.jwt.token_analyser import decode_base64

# Test cases values for decode_base64 function
# Just expected dictionary values.
@pytest.mark.parametrize("expected",
[
    {},
    {"name:": "John Doe"},
    {"alg": "HS256", "typ": "JWT"},
])
def test_decode_base64_when_valid_base64_should_return_decoded_json(expected):
    # dumps converts a Python object into a JSON string,
    # which is the format we need to encode to base64 for testing the decode_base64 function.
    json_text = json.dumps(expected)

    # Encode the input value to base64 for testing
    encoded_value = base64.urlsafe_b64encode(
        json_text.encode("utf-8")
    ).decode("utf-8").rstrip("=")

    # Call the function to decode the base64 value
    actual = decode_base64(encoded_value)

    assert actual == expected, f"The decoded value should match the expected value. Expected: {expected}, Actual: {actual}"

def test_decode_base64_when_decoded_text_is_not_valid_json_should_raise_decode_error():
    invalid_json = "This is not a valid JSON string."

    encoded = base64.urlsafe_b64encode(
        invalid_json.encode("utf-8")
    ).decode("utf-8").rstrip("=")

    with pytest.raises(json.JSONDecodeError):
        decode_base64(encoded)