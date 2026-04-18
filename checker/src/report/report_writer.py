# This file handles report writing functionality.
# Report Writer will accept Final Analysis Result and generate report based on findings
# It will also accept path if -w/--write attribute was provided to save generated to file.
# Otherwise it will display report in console.

import json
from pathlib import Path
from datetime import datetime, timezone
from checker.src.common.severity import Severity
from checker.src.analyser.jwt.token_analysis_result import TokenAnalysisResult
from checker.src.analyser.endpoint.endpoint_validation_result import EndpointValidationResult
from checker.src.analyser.finding import Finding
from checker.src.analyser.final_analysis_result import FinalAnalysisResult

def convert_to_utc(timestamp : int | None) -> str:
    if timestamp is None:
        return "None"
    else:
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return dt.strftime('%d-%m-%Y %H:%M:%S UTC')

def build_report_header(lines: list[str], severity : Severity) -> list[str]:
    lines.append("JWT ENDPOINT CHECKER REPORT")
    lines.append("=" * 60) # insert 60 "=" to create ================
    lines.append(f"Date: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}") # Date in format dd-MM-YYYY hh:mm:ss i.e 12-04-2026 11:12:20
    lines.append(f"Overall Severity: {severity.name.title()}")
    lines.append("")

    return lines

# This function accepts all currently created lines.
# Then accepts token analysis result and builds output text based on it.
def build_jwt_report(lines: list[str], token : TokenAnalysisResult, section_number : int) -> list[str]:
    # JWT TOKEN ANALYSIS
    lines.append("=" * 60)
    lines.append(f"= {section_number}. JWT TOKEN ANALYSIS")
    lines.append("=" * 60)

    if token is None:
        lines.append("Failed to perform JWT token analysis.")
    else:
        lines.append(f"Token: {token['token']}")
        lines.append(f"Valid Format: {'Yes' if token['is_valid_format'] else 'No'}")
        lines.append(f"Segment Count: {token['segment_count']}")
        lines.append(f"Algorithm (alg): {token['alg']}")
        lines.append(f"Subject (sub): {token['alg']}")
        lines.append(f"Expiration (exp): {convert_to_utc(token['exp'])}")
        lines.append(f"Is Expired: {'Expired' if token['is_expired'] else 'Not Expired'}")
        lines.append(f"Signature: {token['signature']}")
        lines.append("")

        # Print out decoded header json if provided
        lines.append("Decoded Header:")
        if token["header"] is None:
            lines.append("None")
        else:
            lines.append(json.dumps(token["header"], indent=4))

        lines.append("")
        lines.append("Decoded Payload:")
        if token["payload"] is None:
            lines.append("None")
        else:
            lines.append(json.dumps(token["payload"], indent=4))

        lines.append("")

    return lines

# This function accepts all currently created lines.
# Then accepts token analysis result and builds output text based on it.
# We are passing and returning section_number as if Endpoint analysis was performed (- e/--endpoint) argument was used
# Then this section will be generated and added to the report output, but in this case we need to track current value of section_number.
# To return multiple values from function I am using tuple to avoid creating separate class or dictionary, for sake of simplicyty.
def build_endpoint_report(lines: list[str], endpoint : EndpointValidationResult | None, section_number : int) -> tuple[list[str], int]:
    if endpoint is not None:
        section_number += 1
        # ENDPOINT ANALYSIS
        lines.append("=" * 60)
        lines.append(f"= {section_number}. ENDPOINT ANALYSIS")
        lines.append("=" * 60)

        lines.append(f"Endpoint URL: {endpoint.endpoint_url}")
        lines.append(f"HTTP Response Code: {endpoint.status_code}")
        lines.append(f"Token used: {endpoint.token}")
        lines.append("")

        lines.append("Response Body: ")
        if endpoint.response:
            lines.append(endpoint.response)
        else:
            lines.append("None")

        lines.append("JSON Response: ")
        if endpoint.response_json is not None:
            lines.append(json.dumps(endpoint.response_json, indent=4))
        else:
            lines.append("None")

    return lines, section_number

# This function accepts all currently created lines.
# Then accepts findings and translate them to more human friendly form
# We need to keep track of section_number here as well
def build_finding_section(lines: list[str], findings : list[Finding], section_number : int) -> tuple[list[str], int]:
    section_number = section_number if not findings else section_number + 1

    # FINDINGS
    lines.append("=" * 60)
    lines.append(f"= {section_number}. FINDINGS")
    lines.append("=" * 60)

    if not findings :
        lines.append("No findings identified")
        lines.append("")
    else:
        # Enumerate all findings and print them as a list starting from 1.
        for index, finding in enumerate(findings):
            lines.append(f"{index +1}: [{finding.severity}] {finding.title}")
            lines.append(f"\tDescription: {finding.description}")
            lines.append("")

            # If finding comes with any recommendations print them as well
            if finding.recommendations:
                lines.append("\t Recommendations:")
                for recommendation in finding.recommendations:
                    lines.append(f"\t\t- {recommendation}")

            lines.append("")

    return lines, section_number

def build_errors_warnings_report(lines: list[str], token: TokenAnalysisResult, endpoint : EndpointValidationResult | None, section_number : int) -> tuple[list[str], int]:

    any_messages = token["errors"] or endpoint.errors or endpoint.warnings
    section_number = section_number if not any_messages else section_number + 1

    # FINDINGS
    lines.append("=" * 60)
    lines.append(f"= {section_number}. FINDINGS")
    lines.append("=" * 60)
# This function builds report from Final Analysis Result into more human-readable form
def build_report(result : FinalAnalysisResult) -> str:
    # Create list to which will add lines and build report.
    # Alternative solution would be to find if there is string builder available for python.
    lines: list[str] = []

    section_number = 1
    token = result.token_analysis
    endpoint = result.endpoint_analysis
    findings = result.findings

    # Print Header
    lines = build_report_header(lines, result.severity)

    # Create JWT Token Section
    lines = build_jwt_report(lines, token, section_number)

    # Create Endpoint Analysis Section
    lines, section_number = build_endpoint_report(lines, endpoint, section_number)

    # Create Findings Section
    lines, section_number = build_finding_section(lines, findings, section_number)

    # Errors and warnings
    lines, section_number = build_finding_section(lines, token, endpoint, section_number)


    return ""

# This function will build report text based on Final Analysis Result,
# Then it will output report to the console.
# Output path parameter is not required and has default value of None.
# Default value allows for function invocation without need of supplying optional parameter.
def output_report(result : FinalAnalysisResult, output_path : str | None = None) -> None: # C# equivalent of void
    report = build_report(result)

    # Print report in CLI
    print(report)

    # If the output path is supplied and leads to existing directory then continue
    # and file name extension is txt, then we know it is a valid path.
    if output_path and ".txt" in output_path and Path(output_path).parent.is_dir():
        Path(output_path).write_text(report, "utf-8")
        print(f"Report has been written to: {output_path}")

    else:
        print("Provided path for report output is invalid.")

