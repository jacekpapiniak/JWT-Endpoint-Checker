from typing import Optional, TypedDict, Any
from checker.src.analyser.finding import Finding

# This class represents the result of JWT token analysis.
# Thanks to TypedDict it is lightweight and flexible type, as it
# only represents shape of the data and not behaviour.
# It allows also for use of more rigid types such as clss Finding.
class TokenAnalysisResult(TypedDict):
    token: str
    is_valid_format: bool
    segment_count: int
    header: dict[str, Any] | None
    payload: dict[str, Any] | None
    signature: Optional[str]
    alg: str | None
    sub: str | None
    exp: int | None
    is_expired: bool | None
    errors: list[str]
    findings: list[Finding] # Finding is a class