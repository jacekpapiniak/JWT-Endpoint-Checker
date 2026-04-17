import base64 # for base64 decoding
import json # for parsing the JSON payload of the JWT token
from checker.src.analyser.jwt.token_analysis_result import TokenAnalysisResult # for defining the structure of the analysis result

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


# Simple check for the "alg" claim in the header.
# The "alg" (algorithm) claim specifies which cryptographic algorithm was used to sign the token.
# APIs rely on this value to correctly verify the token signature.
# If the "alg" claim is missing or incorrect, the API may not be able to validate the token integrity.
# In some misconfigured systems, this can lead to serious vulnerabilities (e.g. accepting unsigned tokens or using the wrong verification method).
# Although the presence of "alg" is required by the JWS (RFC 7515) specification, this check ensures the token header is structurally valid.
def validate_algorithm(header: dict, result: TokenAnalysisResult) -> TokenAnalysisResult:
    if header.get("alg") is not None and header.get("alg") != "":
        result["alg"] = header.get("alg")
    else:
        result["errors"].append("Missing 'alg' claim in header. Required by RFC 7515 (JSON Web Signature).")

    return result


# Simple check fo the "sub" claim in the payload.
# The "sub" claim is a standard claim that allows the api identify whose token it is, and it is typically required for authentication and authorization.
# If the "sub" claim is missing, API should not accept the token for authentication and authorization, as it would not be able to identify the subject of the token.
# However it is not strictly required by the JWT specification, and leads to misconfigurations in token and authentication systems.
def validate_subject(payload: dict, result: TokenAnalysisResult) -> TokenAnalysisResult:
    if payload.get("sub") is None:
        result["errors"].append(
            "Missing 'sub' claim in payload. The 'sub' claim identifies the subject of the token and is typically required for authentication and authorization.")
    if payload.get("sub") == "":
        result["errors"].append(
            "Empty 'sub' claim in payload. The 'sub' claim identifies the subject of the token and is typically required for authentication and authorization.")
    else:
        result["sub"] = payload.get("sub")

    return result

# Simple check for the "exp" claim and validation of the token expiry.
# The "exp" claim is a standard claim that specifies the expiration time of the token as a Unix timestamp (number of seconds since January 1, 1970).
# If the "exp" claim is missing, the API would not be able to determine if the token is expired or not, which can lead to security issues if the token is accepted indefinitely.
def validate_expiry(payload: dict, result: TokenAnalysisResult, current_time_timestamp: int) -> TokenAnalysisResult:
    expiry_time = payload.get("exp")

    # Check if the "exp" claim is present in the payload.
    if expiry_time is None:
        result["errors"].append("Missing 'exp' claim in payload. The 'exp' claim specifies the expiration time of the token and is important for security to prevent accepting expired tokens.")
        return result

    # Check if the "exp" claim is empty string.
    if expiry_time == "":
        result["errors"].append("Empty 'exp' claim in payload. The 'exp' claim should be an integer representing the Unix timestamp of the token's expiration time.")
        return result

    # Check if the "exp" claim is an valid integer representing the Unix timestamp of the token's expiration time.
    if not isinstance(expiry_time,int):
        result["errors"].append("Invalid 'exp' claim in payload. The 'exp' claim should be an integer representing the Unix timestamp of the token's expiration time.")
        return result

    result["exp"] = expiry_time
    # Check if the token is expired by comparing the current time with the expiry time.
    is_expired = current_time_timestamp > expiry_time
    result["is_expired"] = is_expired # Compare the current time with the expiry time to determine if the token is expired
    if is_expired:
        result["errors"].append(f"The token is expired - Current time: {current_time_timestamp}, Expiry time: {expiry_time}.")

    # If it is not expired check if its expiry time is not too far in the future,
    # That can also be a sign of misconfiguration (e.g. tokens that never expire or have very long expiry times can be a security risk if they are leaked).
    # Sometimes expiry times are set to 24hrs or even 7 days, which can be a security risk if the token is leaked, as it would allow an attacker to use the token for a long time.
    # Add a warning if the expiry time is more than 24 hours (86400 seconds) in the future.
    expires_in_seconds = expiry_time - current_time_timestamp
    if expiry_time - current_time_timestamp > 86400:
        result["warnings"].append(f"The token has a long expiry time and expires in {expires_in_seconds} s - Current time: {current_time_timestamp}, Expiry time: {expiry_time}. Consider setting a shorter expiry time for better security.")

    return result

# This function will take a JWT token and perform basic structural analysis.
# Then it returns results of the analysis as a dictionary, which can be used for further processing or display.
def analyse_token(token: str, current_time_timestamp: int) -> TokenAnalysisResult:
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
        "errors": [],
        "warnings": []
    }

    # Split the token into its three parts: header, payload, and signature
    if "." not in token:
        # Valid JWT token has the following structure: header.payload.signature, therefore it must contain two dots.
        # If given token has no dots then it is not valid JWT token
        segments = []
    else:
        # This will return a list of segments after splitting token by the dot char.
        # if s -> return s if it is not null or empty string,
        # otherwise do not include it in the result.
        # C# equivalent would be token.Split('.').Where(s => !string.IsNullOrEmpty(s)).ToList();
        segments = [s for s in token.split(".") if s]

    segment_counts = len(segments)
    result["segment_count"] = segment_counts
    print(f"Token segments: {segments}, Segment count: {segment_counts}")

    if segment_counts != 3:
        result["errors"].append(
            f"Invalid token format. A JWT token must consist of three segments separated by dots. "
            f"Found {segment_counts} {'segment.' if segment_counts == 1 else 'segments.'}")
        return result

    # During decoding the payload and header, as well as parsing the JSON
    # and grabbing the claims, exception can be thrown if the token is not properly formatted,
    # or if the base64 decoding fails, or if the JSON parsing fails.
    try:
        header = decode_base64(segments[0])
        payload = decode_base64(segments[1])

        # We did manage to decode the header and the payload, which means the token is structurally valid, even if it might be missing some important claims.
        result["is_valid_format"] = True
        result["header"] = header
        result["payload"] = payload

        result = validate_algorithm(header, result)
        result = validate_subject(payload, result)
        result = validate_expiry(payload, result, current_time_timestamp)

    except (Exception) as e:
        result["errors"].append(f"Failed to decode JWT: {e}")

    return result