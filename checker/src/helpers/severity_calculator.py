import math

from checker.src.common.severity import Severity
from checker.src.analyser.finding import Finding

# This function accepts collection of Findings
# Then applies hybrid approach to calculate overall system severity
# Hybrid system works as follow:
# - For severities below CRITICAL it calculates average and rounds to the higher severity
# - If at least one CRITICAL in findings, returns CRITICAL
# - If at least one HIGH in finding, returns HIGH
# This avoids underestimating severe security issues while still
# allowing lower-severity findings to influence the final result.

def calculate_overall_severity(findings: list[Finding]) -> Severity:

    # if no findings then return lowest possible severity
    if not findings:
        return Severity.INFO

    # Equivalent to C# .Select(s => s.severity) - creates collection with severities
    severities = [finding.severity for finding in findings]

    # Thanks to use of IntEnum, we can use numerical values to find highest severity detected
    max_severity = max(severities)

    if max_severity == Severity.CRITICAL:
        return  Severity.CRITICAL

    if max_severity == Severity.HIGH:
        return Severity.HIGH

    # Calculate average of lower severity levels
    average = sum(severities) / len(severities)

    # Severity levels have values 0-4, in case of relative value round up to higher severity
    rounded_up = math.ceil(average)

    # Thanks to use of IntEnums we can just cast numerical value to enum.
    return Severity(rounded_up)