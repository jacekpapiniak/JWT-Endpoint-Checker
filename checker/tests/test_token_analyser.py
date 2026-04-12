import pytest
import base64
import json
from checker.src.jwt.token_analyser import decode_base64, analyse_token

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


@pytest.mark.parametrize("token, expected_segment_count, expected_errors",
[
    ("Not even a jwt", 0, ["Invalid token format. A JWT token must consist of three segments separated by dots. Found 0 segments."]),
    ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.", 1, ["Invalid token format. A JWT token must consist of three segments separated by dots. Found 1 segment."]),
    ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2YWxpZEB1c2VyLnRlc3QuY28udWsiLCJlbWFpbCI6InZhbGlkQHVzZXIudGVzdC5jby51ayIsImp0aSI6IjA3Nzk5YWNjLTNlYmYtNGFlOS1iOWRkLTNjN2VjODA1NTI3MyIsImV4cCI6MTc3NTkwNzcxMiwiaXNzIjoiSnd0VGVzdEFwaSIsImF1ZCI6Ikp3dFRlc3RBcGlVc2VycyJ9",
     2, ["Invalid token format. A JWT token must consist of three segments separated by dots. Found 2 segments."]),
])
def test_analyse_token_when_token_has_invalid_format_and_only_one_segment_returns_expected(token: str, expected_segment_count: int, expected_errors: list):
    #This token is not a valid JWT token it only has one segment.
    expected = {
        "token": token,
        "is_valid_format": False,
        "segment_count": expected_segment_count,
        "header": None,
        "payload": None,
        "signature": None,
        "alg" : None,
        "sub" : None,
        "exp" : None,
        "is_expired": None,
        "errors": expected_errors
    }
    actual = analyse_token(token, 1775997355)

    assert actual == expected

def test_analyse_token_when_token_is_expired_returns_expected():
    # This token is a valid JWT token but it is expired as the exp claim is set to a past timestamp.
    expired_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2YWxpZEB1c2VyLnRlc3QuY28udWsiLCJlbWFpbCI6InZhbGlkQHVzZXIudGVzdC5jby51ayIsImp0aSI6IjA3Nzk5YWNjLTNlYmYtNGFlOS1iOWRkLTNjN2VjODA1NTI3MyIsImV4cCI6MTc3NTkwNzcxMiwiaXNzIjoiSnd0VGVzdEFwaSIsImF1ZCI6Ikp3dFRlc3RBcGlVc2VycyJ9.LKodA7Hw5W32FcPzrTDGNXPQpLHVMe_hNieXBwI8ZD4"
    expected = {
        "token": expired_token,
        "is_valid_format": True,
        "segment_count": 3,
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {
                  "sub": "valid@user.test.co.uk",
                  "email": "valid@user.test.co.uk",
                  "jti": "07799acc-3ebf-4ae9-b9dd-3c7ec8055273",
                  "exp": 1775907712, # 11th April 2026
                  "iss": "JwtTestApi",
                  "aud": "JwtTestApiUsers"
                },
        "signature": None,
        "alg" : "HS256",
        "sub" : "valid@user.test.co.uk",
        "exp" : 1775907712, # 11th April 2026
        "is_expired": True,
        "errors": ["The token is expired - Current time: 1775997355, Expiry time: 1775907712."]
    }

    actual = analyse_token(expired_token, 1775997355)

    assert actual == expected

@pytest.mark.parametrize("token, expected_payloads, expected_errors",
[
    ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InZhbGlkQHVzZXIudGVzdC5jby51ayIsImp0aSI6IjA3Nzk5YWNjLTNlYmYtNGFlOS1iOWRkLTNjN2VjODA1NTI3MyIsImV4cCI6MTc3NTkwNzcxMiwiaXNzIjoiSnd0VGVzdEFwaSIsImF1ZCI6Ikp3dFRlc3RBcGlVc2VycyJ9.CDBc0uBuBbM_yBiyL8y7nZafmDcY8imJ_NAXr-bU1bE",
     {
      "email": "valid@user.test.co.uk",
      "jti": "07799acc-3ebf-4ae9-b9dd-3c7ec8055273",
      "exp": 1775907712, # 11th April 2026
      "iss": "JwtTestApi",
      "aud": "JwtTestApiUsers"
    },
    ["Missing 'sub' claim in payload. The 'sub' claim identifies the subject of the token and is typically required for authentication and authorization."]),

    ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIiLCJlbWFpbCI6InZhbGlkQHVzZXIudGVzdC5jby51ayIsImp0aSI6IjA3Nzk5YWNjLTNlYmYtNGFlOS1iOWRkLTNjN2VjODA1NTI3MyIsImV4cCI6MTc3NTkwNzcxMiwiaXNzIjoiSnd0VGVzdEFwaSIsImF1ZCI6Ikp3dFRlc3RBcGlVc2VycyJ9.Yiy36kKs3P_YaSkVeGTwbqp6x2E-Amhu5XjjoMEYNWc",
     {
         "sub": "",
         "email": "valid@user.test.co.uk",
         "jti": "07799acc-3ebf-4ae9-b9dd-3c7ec8055273",
         "exp": 1775907712,  # 11th April 2026
         "iss": "JwtTestApi",
         "aud": "JwtTestApiUsers"
     },
    ["Empty 'sub' claim in payload. The 'sub' claim identifies the subject of the token and is typically required for authentication and authorization."]),
])
def test_analyse_token_when_token_has_missing_or_empty_sub_claim_returns_expected(token:str, expected_payloads: object, expected_errors: list):
    # This token is a valid JWT token but it is missing the alg claim in the header.
    token_missing_alg = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InZhbGlkQHVzZXIudGVzdC5jby51ayIsImp0aSI6IjA3Nzk5YWNjLTNlYmYtNGFlOS1iOWRkLTNjN2VjODA1NTI3MyIsImV4cCI6MTc3NTkwNzcxMiwiaXNzIjoiSnd0VGVzdEFwaSIsImF1ZCI6Ikp3dFRlc3RBcGlVc2VycyJ9.CDBc0uBuBbM_yBiyL8y7nZafmDcY8imJ_NAXr-bU1bE"
    expected = {
        "token": token,
        "is_valid_format": True,
        "segment_count": 3,
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": expected_payloads,
        "signature": None,
        "alg" : "HS256",
        "sub" : None,
        "exp" : 1775907712, # 11th April 2026
        "is_expired": False,
        "errors": expected_errors
    }

    actual = analyse_token(token, 1775907712)

    assert actual == expected