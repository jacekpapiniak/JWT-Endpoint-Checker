# This analyser is going to apply the analysis to the endpoint testing results and the token analysis results,
# then aggregate findings and generate a report based on those results.
import warnings

from checker.src.common.severity import Severity
from checker.src.analyser.finding import Finding
from checker.src.analyser.final_analysis_result import FinalAnalysisResult
from checker.src.analyser.jwt.token_analysis_result import TokenAnalysisResult
from checker.src.analyser.endpoint.endpoint_validation_result import EndpointValidationResult


def analyse_token_result(token_result: TokenAnalysisResult) -> list[Finding]:
    findings = list[Finding] = []
    used_errors = set() # To keep track of errors that we have already used to create findings, so we don't create multiple findings for the same error.

    # Analyze the token analysis results and generate findings based on the results.
    if not token_result["is_valid_format"]:
        # token_analyser.py is adding an error if the token format is invalid,
        # error starts with "Invalid token format", so we can use that to check if the error is related to the token format.
        # If there are multiple errors related to the token format, we will take the first one as the description of the finding.
        # If there are no errors (unlikely) related to the token format, we will use a generic description for the finding.
        description = next(
            (err for err in token_result["errors"] if "Invalid token format" in err),
            "The token is not in a valid JWT format."
        )

        used_errors.add(description) # Mark this error as used, so we don't create another finding for the same error.

        findings.append(Finding(
            title="Invalid JWT Token Format",
            description=description,
            severity=Severity.HIGH,
            recommendations = ["Ensure that the token is a valid JWT token with the correct structure (header.payload.signature)."]
        ))


    # If the token is expired, then build finding based on the error message that token_analyser.py is adding to the errors list when the token is expired.
    if token_result["is_expired"]:
        description = next(
            (err for err in token_result["errors"] if "The token is expired" in err),
            "The token has expired based on the 'exp' claim."
        )

        used_errors.add(description) # Mark this error as used, so we don't create another finding for the same error.

        findings.append(Finding(
            title="Expired JWT Token",
            description=description,
            # The severity set to MEDIUM because an expired token is common issue and sometimes can be accepted by the endpoint.
            severity=Severity.MEDIUM,
            recommendations = ["Obtain a new token that has not expired."]
        ))
    else:
        # However, if the token is not expired,
        # check if there is a warning about the long expiry time of the token,
        # which is added by token_analyser.py when the 'exp' claim is too far in the future.
        warning = next(
            (err for err in token_result["warnings"] if "The token has a long expiry time and expires in" in err),
            ""
        )

        if warning:
            findings.append(Finding(
                title="Token Expiry Time Warning",
                description=warning,
                # The severity set to MEDIUM because a long expiry time is not necessarily a vulnerability,
                # but it can increase the risk of token misuse if the token is compromised.
                # worst case scenario we can have token that never expires, which is a security risk.
                severity=Severity.MEDIUM,
                recommendations= ["Consider reducing the token's expiry time to minimize the risk of token misuse if the token is compromised."]
            ))



    # Analyze the findings for the algorithm used for signing the token, which is specified in the "alg" field of the token header.
    # If the algorithm is "none", then it means that the token is not signed,
    # which is a critical security vulnerability because it allows anyone
    # to tamper with the token and forge it without needing to know any secret key.
    alg = token_result["alg"].lower() if token_result["alg"] else "none"
    if alg == "none":
        findings.append(Finding(
            title="Insecure JWT Algorithm",
            description="The token is using the 'none' algorithm, which means that it is not signed and can be easily tampered with.",
            severity=Severity.CRITICAL,
            recommendations=["Do not use the 'none' algorithm for signing JWT tokens. Use a secure signing algorithm (e.g., HS256, RS256) instead."]
        ))

    # If the algorithm is a symmetric algorithm (HS256, HS384, HS512), then it means that the same secret key is used for both signing and verifying the token,
    # which can be a security risk if the secret key is not managed properly,
    # because if the secret key is compromised, then an attacker can forge tokens and impersonate users or gain unauthorized access to resources.
    elif alg in ["hs256", "hs384", "hs512"]:
        findings.append(Finding(
            title="Symmetric JWT Algorithm Detected",
            description=(
                f"The token is using a symmetric signing algorithm ({token_result['alg']}). "
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
            recommendations= [
                "Ensure strong secret key management and consider using asymmetric algorithms (e.g., RS256) ",
                "for better key separation between issuer and verifier."
            ]
        ))

    elif alg.startswith("rs"):
        findings.append(Finding(
            title="Asymmetric JWT Algorithm Detected",
            description=f"The token uses {token_result['alg']}, which is an asymmetric algorithm.",
            severity=Severity.INFO
        ))

    # Analyse if the subject claim is present in the token, which is commonly used to identify the subject of the token.
    if token_result["sub"] is None:
        findings.append(Finding(
            title="Missing Subject Claim",
            description="The token does not contain a 'sub' claim, which is commonly used to identify the subject of the token.",
            severity=Severity.MEDIUM,
            recommendations=["Consider including a 'sub' claim in the token to identify the subject of the token, which can be useful for authorization and auditing purposes."]
        ))
    elif token_result["sub"]:
        findings.append(Finding(
            title="Subject Claim Detected",
            description=f"The token contains a 'sub' claim with the value: {token_result['sub']}.",
            severity=Severity.INFO
        ))


    for err in token_result["errors"]:
        if "Invalid token format" not in err and "The token is expired" not in err:
            findings.append(Finding(
                title="Other token Analysis Error",
                description=err,
                severity=Severity.MEDIUM
            ))

    return  findings

#This function is going to accept the results of the token analysis and the endpoint analysis,
# and then apply the analysis to those results to generate findings and recommendations.
def analyse_results(token_result : TokenAnalysisResult, endpoint_analysis_result : EndpointValidationResult =None) -> FinalAnalysisResult:
    findings = list[Finding] = []
    token_findings = analyse_token_result(token_result)


    return None