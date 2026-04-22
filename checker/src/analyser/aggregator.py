# This analyser is going to apply the analysis to the endpoint testing results and the token analysis results,
# then aggregate findings and generate a report based on those results.

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
       all_errors.extend(endpoint_result.errors)
       all_findings.extend(endpoint_result.findings)

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