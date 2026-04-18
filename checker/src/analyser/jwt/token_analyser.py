import base64 # for base64 decoding
import json # for parsing the JSON payload of the JWT token
from checker.src.common.severity import Severity
from checker.src.analyser.finding import Finding # for defining the structure of the findings
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

    # Analyze the findings for the algorithm used for signing the token, which is specified in the "alg" field of the token header.
    # If the algorithm is "none", then it means that the token is not signed,
    # which is a critical security vulnerability because it allows anyone
    # to tamper with the token and forge it without needing to know any secret key.
    alg = header.get("alg").lower() if header.get("alg") else "none"

    if header.get("alg") is None:
        result["findings"].append(Finding(
            title="Missing 'alg' Claim in JWT Header",
            description='''
                The 'alg' claim is missing in the JWT header. 
                This claim specifies the algorithm used to sign the token and is required for proper token validation.''',
            severity=Severity.CRITICAL,
            recommendations=[
                "Ensure that the JWT token includes the 'alg' claim in the header, specifying the signing algorithm used (e.g., HS256, RS256).",
                "Review the token generation process to include the 'alg' claim as per RFC 7515 (JSON Web Signature) specifications."
            ]
        ))
    elif header.get("alg") == "":
        result["findings"].append(Finding(
            title="Empty 'alg' Claim in JWT Header",
            description='''
                The empty 'alg' claim in the JWT header. 
                This claim specifies the algorithm used to sign the token and is required for proper token validation.''',
            severity=Severity.CRITICAL,
            recommendations=[
                "Ensure that the JWT token includes the 'alg' claim in the header, specifying the signing algorithm used (e.g., HS256, RS256).",
                "Review the token generation process to include the 'alg' claim as per RFC 7515 (JSON Web Signature) specifications."
            ]
        ))
    # If the algorithm is a symmetric algorithm (HS256, HS384, HS512), then it means that the same secret key is used for both signing and verifying the token,
    # which can be a security risk if the secret key is not managed properly,
    # because if the secret key is compromised, then an attacker can forge tokens and impersonate users or gain unauthorized access to resources.
    elif alg in ["hs256", "hs384", "hs512"]:
        result["findings"].append(Finding(
            title="Symmetric JWT Algorithm Detected",
            description=(
                f"The token is using a symmetric signing algorithm ({alg}). "
                "This requires secure management of the shared secret, as compromise of the secret "
                "allows full token forgery."
            ),
            # The severity is LOW because sha 256, 384 and 512 are currently considered secure algorithms,
            # They are also widely used in JWT tokens.
            # However, it is important to note that the security of the token also depends on how the secret key is managed and protected.
            # If the secret key is weak or compromised, then it can lead to token forgery and unauthorized access, even if a secure algorithm is used.
            # The likelihood of the secret key being compromised is relatively low if proper key management is introduced.
            # The best practice for using symmetric algorithms is to ensure that the secret key is strong, kept confidential, and rotated regularly.
            # In some cases, it might be better to use asymmetric algorithms (e.g., RS256) for better key separation between the issuer and the verifier,
            # which can enhance security by reducing the risk of key compromise.
            severity=Severity.LOW,
            recommendations=[
                "Ensure strong secret key management and consider using asymmetric algorithms "
                "(e.g., RS256) for better key separation between issuer and verifier."
            ]
        ))
    elif alg.startswith("rs"):
        result["findings"].append(Finding(
            title="Asymmetric JWT Algorithm Detected",
            description=f"The token uses {alg}, which is an asymmetric algorithm.",
            severity=Severity.INFO
        ))

    return result


# Simple check fo the "sub" claim in the payload.
# The "sub" claim is a standard claim that allows the api identify whose token it is, and it is typically required for authentication and authorization.
# If the "sub" claim is missing, API should not accept the token for authentication and authorization, as it would not be able to identify the subject of the token.
# However it is not strictly required by the JWT specification, and leads to misconfigurations in token and authentication systems.
def validate_subject(payload: dict, result: TokenAnalysisResult) -> TokenAnalysisResult:
    if payload.get("sub") is None:
        result["findings"].append(Finding(
            title="Missing 'sub' Claim in JWT Payload",
            description='''
            The 'sub' claim is missing in the JWT payload. 
            This claim identifies the subject of the token and is typically required for authentication and authorization.''',
            severity=Severity.MEDIUM,
            recommendations=[
                "Ensure that the JWT token includes the 'sub' claim in the payload, specifying the subject of the token (e.g., user ID, email).",
                "Review the token generation process to include the 'sub' claim as per JWT best practices."]
        ))
    elif payload.get("sub") == "":
        result["findings"].append(Finding(
            title="Empty 'sub' Claim in JWT Payload",
            description='''
            The empty 'sub' claim in the JWT payload. 
            This claim identifies the subject of the token and should not be empty for proper authentication and authorization.''',
            severity=Severity.MEDIUM,
            recommendations=[
                "Ensure that the 'sub' claim in the JWT payload is not empty and correctly identifies the subject of the token (e.g., user ID, email).",
                "Review the token generation process to ensure that the 'sub' claim is populated with meaningful information as per JWT best practices."
            ]
        ))
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
        result["findings"].append(Finding(
            title="Missing 'exp' Claim in JWT Payload",
            description='''
            The 'exp' claim is missing in the JWT payload. 
            This claim specifies the expiration time of the token and is important for security to prevent accepting expired tokens.''',
            severity=Severity.HIGH,
            recommendations=[
                "Ensure that the JWT token includes the 'exp' claim in the payload, specifying the expiration time of the token as a Unix timestamp.",
                "Review the token generation process to include the 'exp' claim as per JWT best practices."
            ]
        ))
        return result

    # Check if the "exp" claim is empty string.
    if expiry_time == "":
        result["findings"].append(Finding(
            title="Empty 'exp' Claim in JWT Payload",
            description='''
            The 'exp' claim in the JWT payload is empty. 
            This claim should be an integer representing the Unix timestamp of the token's expiration time.''',
            severity=Severity.HIGH,
            recommendations=[
                "Ensure that the 'exp' claim in the JWT payload is not empty and correctly specifies the expiration time of the token as a Unix timestamp.",
                "Review the token generation process to ensure that the 'exp' claim is populated with a valid timestamp as per JWT best practices."
            ]
        ))

        return result

    # Check if the "exp" claim is an valid integer representing the Unix timestamp of the token's expiration time.
    if not isinstance(expiry_time,int):
        result["findings"].append(Finding(
            title="Invalid 'exp' Claim in JWT Payload",
            description='''
            The 'exp' claim in the JWT payload is not a valid integer. 
            This claim should be an integer representing the Unix timestamp of the token's expiration time.''',
            severity=Severity.HIGH,
            recommendations=[
                "Ensure that the 'exp' claim in the JWT payload is a valid integer and correctly specifies the expiration time of the token as a Unix timestamp.",
                "Review the token generation process to ensure that the 'exp' claim is populated with a valid timestamp as per JWT best practices."
            ]
        ))
        return result

    result["exp"] = expiry_time
    # Check if the token is expired by comparing the current time with the expiry time.
    is_expired = current_time_timestamp > expiry_time
    result["is_expired"] = is_expired # Compare the current time with the expiry time to determine if the token is expired
    if is_expired:
        result["findings"].append(Finding(
            title="Expired JWT Token",
            description=f'''
            The token is expired based on the 'exp' claim. 
            Current time: {current_time_timestamp}, Expiry time: {expiry_time}.''',
            severity=Severity.MEDIUM,
            recommendations=[
                "Obtain a new token that has not expired.",
                "Review the token generation process to ensure that tokens have appropriate expiration times as per JWT best practices."
            ]
        ))

    # If it is not expired check if its expiry time is not too far in the future,
    # That can also be a sign of misconfiguration (e.g. tokens that never expire or have very long expiry times can be a security risk if they are leaked).
    # Sometimes expiry times are set to 24hrs or even 7 days, which can be a security risk if the token is leaked, as it would allow an attacker to use the token for a long time.
    # Add a warning if the expiry time is more than 24 hours (86400 seconds) in the future.
    expires_in_seconds = expiry_time - current_time_timestamp
    if expiry_time - current_time_timestamp > 86400:
        result["findings"].append(Finding(
            title="Token With Long Expiry Time",
            description=f'''
            The token has a long expiry time and expires in {expires_in_seconds} seconds. 
            Current time: {current_time_timestamp}, Expiry time: {expiry_time}. 
            Consider setting a shorter expiry time for better security.''',
            severity=Severity.MEDIUM,
            recommendations=[
                "Consider reducing the token's expiry time to minimize the risk of token misuse if the token is compromised.",
                "Review the token generation process to ensure that tokens have appropriate expiration times as per JWT best practices."
            ]
        ))
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
        "findings": []
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
        description =(
            f"Invalid token format. A JWT token must consist of three segments separated by dots. "
            f"Found {segment_counts} {'segment.' if segment_counts == 1 else 'segments.'}")

        result["findings"].append(Finding(
            title="Invalid token format.",
            description= description,
            severity= Severity.HIGH,
            recommendations=["Use valid JWT token in valid format header.payload.signature according with RFC 7519 (JSON Web Token)."]
        ))

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
        result["findings"].append(Finding(
            title="JWT decoding failed",
            description=f"Failed to decode JWT: {e}",
            severity=Severity.MEDIUM,
            recommendations=[
                "Ensure the token is properly Base64URL encoded and contains valid JSON."
            ]
        ))
        result["errors"].append(f"Failed to decode JWT: {e}")


    return result