from checker.src.helpers.severity_calculator import calculate_overall_severity
from checker.src.common.severity import Severity
from checker.src.analyser.finding import Finding

def test_calculate_overall_severity_when_at_least_one_critical_returns_critical():
    findings = [
            Finding(severity= Severity.CRITICAL),
            Finding(severity= Severity.HIGH),
            Finding(severity= Severity.LOW),
        ]

    actual = calculate_overall_severity(findings)

    assert actual == Severity.CRITICAL

# The way the severity is calculated is not ideal, it is an hybrid approach that returns High and Critical if there is at least one of them
# in the findings. For anything below that the average is calculated.
# Problem with that is that many low value severities can significantly drag down the overall severity.
# I am leaving this approach knowingly to demonstrate this problem.
# I hope that the tests represents this issue sufficiently

def test_calculate_overall_severity_when_at_least_one_high_returns_high():
    findings = [
            Finding(severity= Severity.HIGH),
            Finding(severity= Severity.MEDIUM),
            Finding(severity= Severity.LOW),
        ]

    actual = calculate_overall_severity(findings)

    assert actual == Severity.HIGH

def test_calculate_overall_severity_calculate_average_no_round_up():
    findings = [
            Finding(severity= Severity.MEDIUM),
            Finding(severity= Severity.LOW),
            Finding(severity= Severity.LOW)
        ]

    actual = calculate_overall_severity(findings)

    assert actual == Severity.MEDIUM

def test_calculate_overall_severity_calculate_average_round_up_to_low():
    findings = [
            Finding(severity= Severity.INFO),
            Finding(severity= Severity.MEDIUM),
            Finding(severity= Severity.LOW),
            Finding(severity= Severity.LOW)
        ]

    actual = calculate_overall_severity(findings)

    assert actual == Severity.LOW

def test_calculate_overall_severity_calculate_average_round_up_to_medium():
    findings = [
            Finding(severity= Severity.MEDIUM),
            Finding(severity= Severity.LOW)
        ]

    actual = calculate_overall_severity(findings)

    assert actual == Severity.MEDIUM