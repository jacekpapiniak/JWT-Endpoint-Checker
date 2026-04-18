# This analyser is going to apply the analysis to the endpoint testing results and the token analysis results,
# then aggregate findings and generate a report based on those results.

from checker.src.common.severity import Severity
from checker.src.analyser.finding import Finding
from checker.src.analyser.final_analysis_result import FinalAnalysisResult
from checker.src.analyser.jwt.token_analysis_result import TokenAnalysisResult
from checker.src.analyser.endpoint.endpoint_validation_result import EndpointValidationResult
from checker.src.helpers.severity_calculator import calculate_overall_severity


#This function is going to accept the results of the token analysis and the endpoint analysis,
# and then apply the analysis to those results to generate findings and recommendations.
def analyse_results(token_result : TokenAnalysisResult, endpoint_result : EndpointValidationResult =None) -> FinalAnalysisResult:
    summary = ""
    all_errors = []
    all_errors.extend(token_result["errors"])
    all_findings = []
    all_findings.extend(token_result["findings"])

    # The endpoint analysis_result contains all details about request performed with use of already analysed jwt token
    # Now this part is cross-check with jwt token to validate if the call should be accepted or not.
    if endpoint_result is not None:
       status_code = endpoint_result.status_code
       all_errors.extend(endpoint_result.errors)

       # Check if malformed jwt token was successfully accepted by endpoint
       if token_result["is_valid_format"] is False and status_code == 200 :
           all_findings.append(Finding(
               title="Endpoint accepted malformed token.",
               description=(
                   f"The endpoint {endpoint_result.endpoint_url} returned HTTP 200 (OK)"
                   "with JWT token with invalid format."
               ),
               severity= Severity.CRITICAL,
               recommendations=[
                   "Ensure that JWT toke structure is validated by the endpoint before processing authorization."
               ]
           ))

       # Check if expired jwt token was successfully accepted by endpoint
       if token_result["is_expired"] is True and status_code == 200 :
           all_findings.append(Finding(
               title="Endpoint accepted expired token.",
               description=(
                   f"The endpoint {endpoint_result.endpoint_url} returned HTTP 200 (OK)"
                   "with expired JWT token."
               ),
               severity= Severity.HIGH,
               recommendations=[
                   "Ensure that endpoint validates JWT tokens expiration."
               ]
           ))

       # Check if no subject set but token accepted
       if token_result["sub"] is None and status_code == 200 :
           all_findings.append(Finding(
               title="Endpoint accepted token with missing subject claim.",
               description=(
                   f"The endpoint {endpoint_result.endpoint_url} returned HTTP 200 (OK)"
                   "with missing subject claim in JWT token."
               ),
               severity= Severity.HIGH,
               recommendations=[
                   "Require identity-related claims such as 'sub' before authorizing requests."
               ]
           ))

       # Check if empty subject set but token accepted
       if token_result["sub"] == "" and status_code == 200 :
           all_findings.append(Finding(
               title="Endpoint accepted token with empty subject claim.",
               description=(
                   f"The endpoint {endpoint_result.endpoint_url} returned HTTP 200 (OK)"
                   "with empty subject claim in JWT token."
               ),
               severity= Severity.HIGH,
               recommendations=[
                   "Ensure identity-related claims such as 'sub' validation before authorizing requests."
               ]
           ))

       # Check server-side error handling
       if status_code >= 500:
           all_findings.append(Finding(
               title="Endpoint returned server error",
               description=(
                   f"The endpoint returned HTTP {status_code}. "
                   "This may indicate weak input validation or unhandled exceptions."
               ),
               severity=Severity.MEDIUM,
               recommendations=[
                   "Handle invalid or malformed tokens safely and return controlled 4xx responses instead of 5xx errors."
               ]
           ))

       severity = calculate_overall_severity(all_findings)

       if all_findings:
            summary = (
                f"Analysis completed with {len(all_findings)} finding(s). "
                f"Overall severity: {severity.name}."
            )
       else:
            summary = "Analysis completed with no significant findings."

       return FinalAnalysisResult(
        summary=summary,
        severity=severity,
        token_analysis=token_result,
        endpoint_analysis=endpoint_result,
        findings=all_findings)