import base64 # for base64 decoding
import json # for parsing the JSON payload of the JWT token
from datetime import datetime, timezone # for converting the exp claim to a human-readable format

def calculate_missing_padding(token_part: str, multiply_factor: int) -> int:
    # Calculate the number of padding characters needed
    # The below calculation calculates what is the remainder when the given length of the token
    # is not a multiple of 4, then it calculates how many characters we need to add to it
    # to make this tokens length a multiple of 4, which is required for base64 decoding.
    # i.e if the length of the token part is 22,
    # then (4 - (22 % 4)) -> 4 - 2 = 2 -> 2 % 4 = 2 , and we need to add 2 more characters to make it a multiple of 4 (24)
    # There are two % 4 operations in the calculation to handle the case when the length is already a multiple of 4, in which case we don't need to add any padding.
    # For example, if the length of the token part is 40, then (4 - (40 % 4)) -> 4 - 0 = 4 - this would be wrong as it would mean we need 4 more characters
    # So to counter this we have  (4 -(40 % 4)) % 4 -> (4 - 0) % 4 -> 4 % 4 = 0, and we don't need to add any padding.
    missing_padding = (multiply_factor - len(token_part) % multiply_factor) % multiply_factor
    return missing_padding

# Jwt token format is "header.payload.signature"
# Header and payload are base64 encoded JSON objects, and signature is a string.
# Therefore to decode the header and payload we need to decode base 64 to string.
def decode_base64_to_json(token_part: str) -> dict:
    # Add required padding if necessary
    # Base64 encoding requires that the length of the encoded string be a multiple of 4.
    # If it's not, we need to add padding characters ("=") to make it a multiple of 4 before decoding.
    missing_padding = calculate_missing_padding(token_part, 4)
    padding = "=" * missing_padding

    # Decode the base64 to bytes
    # Base 64 always adds = padding characters at the end of the encoded string to make its length mod 4
    # So we have to do token + padding as it reads left to right
    # the "=" padding means this is end of data
    # therefore we cannot do padding + token as it would mean the rest of token would be ignored
    decoded_bytes = base64.urlsafe_b64decode(token_part + padding)
    # Convert the decoded bytes to a string
    decoded_text = decoded_bytes.decode("utf-8")
    # Parse the decoded string as JSON and return it as a dictionary
    return json.loads(decoded_text)

# This function takes a JWT token as input and returns a dictionary with the following information:
# - "header": the decoded header of the JWT token as a dictionary
# - "payload": the decoded payload of the JWT token as a dictionary
# - "signature": the signature of the JWT token as a string
# - "is_expired": a boolean indicating whether the token is expired based on the "exp" claim in the payload
def analyse_token(token: str) -> dict:
