from typing import Optional, TypedDict, Any

# This class represnts the results of the jwt token analysis.
# It is a TypedDict, which is a special type of dictionary that allows us to specify the types of the keys and values.
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
    warnings: list[str]