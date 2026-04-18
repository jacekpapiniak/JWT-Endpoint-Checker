from dataclasses import dataclass, field
from checker.src.common.severity import Severity
from checker.src.analyser.finding import Finding
from checker.src.analyser.jwt.token_analysis_result import TokenAnalysisResult
from checker.src.analyser.endpoint.endpoint_validation_result import EndpointValidationResult

# This class represents the final analysis result that will be generated after analysing the token and the endpoint.

@dataclass
class FinalAnalysisResult:
    summary: str
    # The overall severity of the report, which is calculated based on the findings.
    # The severity of the report is determined by the average rounded to the higher severity.
    # For example, if there are 3 findings with severity levels LOW, MEDIUM, and HIGH, the average severity would be (1 + 2 + 3) / 3 = 2, which corresponds to MEDIUM.
    severity: Severity
    token_analysis: TokenAnalysisResult
    endpoint_analysis: EndpointValidationResult
    findings: list[Finding] = field(default_factory=list)