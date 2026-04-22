from checker.src.analyser.finding import Finding
from dataclasses import dataclass, field
from typing import Optional
# This class holds the results of the endpoint validation.
# It will be used to store the results of the endpoint validation.
# It will store:
# - the endpoint url
# - the response from the endpoint
# - the status code of the response
# - whether the validation passed or not
# - any errors that were found during the validation
# - any warnings that were found during the validation

@dataclass
class EndpointValidationResult:
    endpoint_url: str
    token: str
    response: str = ""
    status_code: int = 0
    response_json: Optional[dict] = None
    findings : list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list) # We use default_factory to initialize the errors list as an empty list by default.
    warnings: list[str] = field(default_factory=list) # We use default_factory to initialize the warnings list as an empty list by default.