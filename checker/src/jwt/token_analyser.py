import base64 # for base64 decoding
import json # for parsing the JSON payload of the JWT token
from checker.src.jwt.token_analysis_result import TokenAnalysisResult # for defining the structure of the analysis result
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
def decode_base64(token_part: str) -> dict:
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

# This function will take a JWT token and perform basic structural analysis.
# Then it returns results of the analysis as a dictionary, which can be used for further processing or display.
def analyse_token(token: str) -> TokenAnalysisResult:
    print(f"Analyzing token: {token}...")
    result : TokenAnalysisResult = {
        "token": token,
        "is_valid_format": False,
        "segment_count": 0,
        "header": None,
        "payload": None,
        # This is optional for now as we would need to know the signing algorithm and secret key to verify
        # the signature, which is out of scope for this basic analysis.
        "signature": None,
        "alg" : None,
        "sub" : None,
        "exp" : None,
        "is_expired": None,
        "errors": []
    }

    # Split the token into its three parts: header, payload, and signature
    segments = token.split(".")
    segment_counts = len(segments)
    result["segment_count"] = segment_counts

    if segment_counts != 3:
        result["errors"].append(f"Invalid token format. A JWT token must consist of three segments separated by dots. Found {segment_counts} segments.")
        return result

    # During decoding the payload and header, as well as parsing the JSON
    # and grabbing the claims, exception can be thrown if the token is not properly formatted,
    # or if the base64 decoding fails, or if the JSON parsing fails.
    try:
        header = decode_base64(segments[0])
        payload = decode_base64(segments[1])
        result["is_valid_format"] = True
        result["header"] = header
        result["payload"] = payload
        result["alg"] = header.get("alg")
        result["sub"] = payload.get("sub")
        result["exp"] = payload.get("exp")

        expiry_time = payload.get("exp")
        # isinstance check is to ensure that the exp claim is a valid integer timestamp before we try to compare it with the current time.
        if expiry_time is not None and isinstance(expiry_time,int):
            current_time = int(datetime.now(timezone.utc).timestamp()) # Get the current time in UTC as a timestamp
            is_expired = current_time > expiry_time
            result["is_expired"] = is_expired # Compare the current time with the expiry time to determine if the token is expired

            if is_expired:
                result["errors"].append(f"The token is expired - Current time: {current_time}, Expiry time: {expiry_time}.")
        else:
            result["errors"].append("The 'exp' claim is missing or is not a valid integer timestamp, so we cannot determine if the token is expired.")

    except (Exception) as e:
        result["errors"].append(f"Failed to decode JWT: {e}")

    return result