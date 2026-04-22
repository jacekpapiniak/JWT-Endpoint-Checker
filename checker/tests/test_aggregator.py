import json
from checker.src.analyser.jwt.token_analysis_result import TokenAnalysisResult
from checker.src.common.severity import Severity
from checker.src.analyser.finding import Finding
from checker.src.analyser.endpoint.endpoint_validation_result import EndpointValidationResult
from checker.src.analyser.final_analysis_result import FinalAnalysisResult
from checker.src.analyser.aggregator import analyse_results

url = "http://superhacky.co.uk:5000/api/login"
secured_endpoint_url = "http://superhacky.co.uk:5000/api/profile"

successful_json_response = {
    "name": "Valid User",
    "email": "valid@user.test.co.uk",
    "role": "Student"
}

def test_analyse_results_when_endpoint_result_is_none_return_expected():
    valid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2YWxpZEB1c2VyLnRlc3QuY28udWsiLCJlbWFpbCI6InZhbGlkQHVzZXIudGVzdC5jby51ayIsImp0aSI6IjA3Nzk5YWNjLTNlYmYtNGFlOS1iOWRkLTNjN2VjODA1NTI3MyIsImV4cCI6MTc3NTkwNzcxMiwiaXNzIjoiSnd0VGVzdEFwaSIsImF1ZCI6Ikp3dFRlc3RBcGlVc2VycyJ9.LKodA7Hw5W32FcPzrTDGNXPQpLHVMe_hNieXBwI8ZD4"
    token_result : TokenAnalysisResult = {
        "token": valid_token,
        "is_valid_format": True,
        "segment_count": 3,
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {
                  "sub": "valid@user.test.co.uk",
                  "email": "valid@user.test.co.uk",
                  "jti": "07799acc-3ebf-4ae9-b9dd-3c7ec8055273",
                  "exp": 1775907712, # 11th April 2026
                  "iss": "JwtTestApi",
                  "aud": "JwtTestApiUsers"
                },
        "signature": None,
        "alg" : "HS256",
        "sub" : "valid@user.test.co.uk",
        "exp" : 1775907712, # 11th April 2026
        "is_expired": False,
        "errors": [],
        "findings" : [
            Finding(
                title='Symmetric JWT Algorithm Detected',
                severity= Severity.LOW,
                description='The token is using a symmetric signing algorithm (hs256). This requires secure management of the shared secret, as compromise of the secret allows full token forgery.',
                recommendations=['Ensure strong secret key management and consider using asymmetric algorithms (e.g., RS256) for better key separation between issuer and verifier.'])
        ]
    }

    actual = analyse_results(token_result, None)

    assert actual == FinalAnalysisResult(
        summary='Analysis completed with 1 finding(s). Overall severity: LOW.',
        severity= Severity.LOW,
        token_analysis=token_result,
        endpoint_analysis=None,
        findings= token_result["findings"])

def test_analyse_results_when_endpoint_result_is_some_and_malformed_jwt_accepted_by_endpoint_return_expected():
    token = "Not even a jwt"
    token_result : TokenAnalysisResult = {
        "token": token,
        "is_valid_format": False,
        "segment_count": 0,
        "header": None,
        "payload": None,
        "signature": None,
        "alg" : None,
        "sub" : None,
        "exp" : None,
        "is_expired": None,
        "errors": [],
        "findings" : [
            Finding(
                title='Invalid token format.',
                severity= Severity.HIGH,
                description = "Invalid token format. A JWT token must consist of three segments separated by dots. Found 0 segments.",
                recommendations = ["Use valid JWT token in valid format header.payload.signature according with RFC 7519 (JSON Web Token)."])
        ]
    }
    endpoint_result : EndpointValidationResult = EndpointValidationResult(
        endpoint_url=secured_endpoint_url,
        token= token,
        response=json.dumps(successful_json_response),
        response_json= successful_json_response,
        status_code=200,
        errors=[],
        warnings=[],
        findings=[
            Finding(
                title='Endpoint accepted malformed token.',
                severity=Severity.CRITICAL,
                description=f'The endpoint {secured_endpoint_url} returned HTTP 200 (OK)with JWT token with invalid format.',
                recommendations=['Ensure that JWT toke structure is validated by the endpoint before processing authorization.']),

            Finding(
                title='Endpoint accepted token with missing subject claim.',
                severity=Severity.HIGH,
                description=f'The endpoint {secured_endpoint_url} returned HTTP 200 (OK)with missing subject claim in JWT token.',
                recommendations=["Require identity-related claims such as 'sub' before authorizing requests."])
        ])

    actual = analyse_results(token_result, endpoint_result)

    assert actual == FinalAnalysisResult(
        summary='Analysis completed with 3 finding(s). Overall severity: CRITICAL.',
        severity= Severity.CRITICAL,
        token_analysis= token_result,
        endpoint_analysis= endpoint_result,
        findings=[
            Finding(
                title='Invalid token format.',
                severity= Severity.HIGH,
                description='Invalid token format. A JWT token must consist of three segments separated by dots. Found 0 segments.',
                recommendations=['Use valid JWT token in valid format header.payload.signature according with RFC 7519 (JSON Web Token).']),

            Finding(
                title='Endpoint accepted malformed token.',
                severity=Severity.CRITICAL,
                description=f'The endpoint {secured_endpoint_url} returned HTTP 200 (OK)with JWT token with invalid format.',
                recommendations=['Ensure that JWT toke structure is validated by the endpoint before processing authorization.']),

            Finding(
                title='Endpoint accepted token with missing subject claim.',
                severity=Severity.HIGH,
                description=f'The endpoint {secured_endpoint_url} returned HTTP 200 (OK)with missing subject claim in JWT token.',
                recommendations=["Require identity-related claims such as 'sub' before authorizing requests."])
        ]
    )

def test_analyse_results_when_endpoint_result_is_some_and_expired_jwt_accepted_by_endpoint_return_expected():
    expired_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2YWxpZEB1c2VyLnRlc3QuY28udWsiLCJlbWFpbCI6InZhbGlkQHVzZXIudGVzdC5jby51ayIsImp0aSI6IjA3Nzk5YWNjLTNlYmYtNGFlOS1iOWRkLTNjN2VjODA1NTI3MyIsImV4cCI6MTc3NTkwNzcxMiwiaXNzIjoiSnd0VGVzdEFwaSIsImF1ZCI6Ikp3dFRlc3RBcGlVc2VycyJ9.LKodA7Hw5W32FcPzrTDGNXPQpLHVMe_hNieXBwI8ZD4"
    token_result : TokenAnalysisResult = {
        "token": expired_token,
        "is_valid_format": True,
        "segment_count": 3,
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {
                  "sub": "valid@user.test.co.uk",
                  "email": "valid@user.test.co.uk",
                  "jti": "07799acc-3ebf-4ae9-b9dd-3c7ec8055273",
                  "exp": 1775907712, # 11th April 2026
                  "iss": "JwtTestApi",
                  "aud": "JwtTestApiUsers"
                },
        "signature": None,
        "alg" : "HS256",
        "sub" : "valid@user.test.co.uk",
        "exp" : 1775907712, # 11th April 2026
        "is_expired": True,
        "errors": [],
        "findings": [
            Finding(
                title='Symmetric JWT Algorithm Detected',
                severity=Severity.LOW,
                description='The token is using a symmetric signing algorithm (hs256). This requires secure management of the shared secret, as compromise of the secret allows full token forgery.',
                recommendations=[
                    'Ensure strong secret key management and consider using asymmetric algorithms (e.g., RS256) for better key separation between issuer and verifier.']),
            Finding(
                title='Expired JWT Token',
                severity=Severity.MEDIUM,
                description="\n            The token is expired based on the 'exp' claim. \n            Current time: 1775997355, Expiry time: 1775907712.",
                recommendations=[
                    'Obtain a new token that has not expired.',
                    'Review the token generation process to ensure that tokens have appropriate expiration times as per JWT best practices.'])
        ]
    }
    endpoint_result : EndpointValidationResult = EndpointValidationResult(
        endpoint_url= secured_endpoint_url,
        token= expired_token,
        response=json.dumps(successful_json_response),
        response_json= successful_json_response,
        status_code=200,
        errors=[],
        warnings=[],
        findings=[
            Finding(
                title='Endpoint accepted expired token.',
                severity=Severity.HIGH,
                description=f'The endpoint {secured_endpoint_url} returned HTTP 200 (OK)with expired JWT token.',
                recommendations=['Ensure that endpoint validates JWT tokens expiration.']
        )])

    actual = analyse_results(token_result, endpoint_result)

    assert actual == FinalAnalysisResult(
        summary='Analysis completed with 3 finding(s). Overall severity: HIGH.',
        severity= Severity.HIGH,
        token_analysis= token_result,
        endpoint_analysis= endpoint_result,
        findings= [
            Finding(
                title='Symmetric JWT Algorithm Detected',
                severity= Severity.LOW,
                description='The token is using a symmetric signing algorithm (hs256). This requires secure management of the shared secret, as compromise of the secret allows full token forgery.',
                recommendations=['Ensure strong secret key management and consider using asymmetric algorithms (e.g., RS256) for better key separation between issuer and verifier.']),

            Finding(
                title='Expired JWT Token',
                severity= Severity.MEDIUM, description="\n            The token is expired based on the 'exp' claim. \n            Current time: 1775997355, Expiry time: 1775907712.",
                recommendations=['Obtain a new token that has not expired.',
                                 'Review the token generation process to ensure that tokens have appropriate expiration times as per JWT best practices.']),

            Finding(
                title='Endpoint accepted expired token.',
                severity=Severity.HIGH,
                description=f'The endpoint {secured_endpoint_url} returned HTTP 200 (OK)with expired JWT token.',
                recommendations=['Ensure that endpoint validates JWT tokens expiration.']
            )
        ])

def test_analyse_results_when_endpoint_result_is_some_and_no_sub_set_in_jwt_accepted_by_endpoint_return_expected():
    no_sub_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InZhbGlkQHVzZXIudGVzdC5jby51ayIsImp0aSI6IjA3Nzk5YWNjLTNlYmYtNGFlOS1iOWRkLTNjN2VjODA1NTI3MyIsImV4cCI6MTc3NTkwNzcxMiwiaXNzIjoiSnd0VGVzdEFwaSIsImF1ZCI6Ikp3dFRlc3RBcGlVc2VycyJ9.CDBc0uBuBbM_yBiyL8y7nZafmDcY8imJ_NAXr-bU1bE"
    token_result : TokenAnalysisResult = {
        "token": no_sub_token,
        "is_valid_format": True,
        "segment_count": 3,
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {
          "email": "valid@user.test.co.uk",
          "jti": "07799acc-3ebf-4ae9-b9dd-3c7ec8055273",
          "exp": 1775907712, # 11th April 2026
          "iss": "JwtTestApi",
          "aud": "JwtTestApiUsers"
        },
        "signature": None,
        "alg" : "HS256",
        "sub" : None,
        "exp" : 1775907712, # 11th April 2026
        "is_expired": False,
        "errors": [],
        "findings": [
         Finding(
             title='Symmetric JWT Algorithm Detected',
             severity=Severity.LOW,
             description='The token is using a symmetric signing algorithm (hs256). This requires secure management of the shared secret, as compromise of the secret allows full token forgery.',
             recommendations=[
                 'Ensure strong secret key management and consider using asymmetric algorithms (e.g., RS256) for better key separation between issuer and verifier.']),

         Finding(
             title="Missing 'sub' Claim in JWT Payload",
             severity=Severity.MEDIUM,
             description="\n            The 'sub' claim is missing in the JWT payload. \n            This claim identifies the subject of the token and is typically required for authentication and authorization.",
             recommendations=[
                 "Ensure that the JWT token includes the 'sub' claim in the payload, specifying the subject of the token (e.g., user ID, email).",
                 "Review the token generation process to include the 'sub' claim as per JWT best practices."])
     ]
    }
    endpoint_result : EndpointValidationResult = EndpointValidationResult(
        endpoint_url= secured_endpoint_url,
        token= no_sub_token,
        response=json.dumps(successful_json_response),
        response_json= successful_json_response,
        status_code=200,
        errors=[],
        warnings=[],
        findings=[
            Finding(
                title='Endpoint accepted token with missing subject claim.',
                severity=Severity.HIGH,
                description=f'The endpoint {secured_endpoint_url} returned HTTP 200 (OK)with missing subject claim in JWT token.',
                recommendations=["Require identity-related claims such as 'sub' before authorizing requests."])
    ])

    actual = analyse_results(token_result, endpoint_result)

    assert actual == FinalAnalysisResult(
        summary='Analysis completed with 3 finding(s). Overall severity: HIGH.',
        severity= Severity.HIGH,
        token_analysis= token_result,
        endpoint_analysis= endpoint_result,
        findings= [
            Finding(
                title='Symmetric JWT Algorithm Detected',
                severity= Severity.LOW,
                description='The token is using a symmetric signing algorithm (hs256). This requires secure management of the shared secret, as compromise of the secret allows full token forgery.',
                recommendations=['Ensure strong secret key management and consider using asymmetric algorithms (e.g., RS256) for better key separation between issuer and verifier.']),

            Finding(
                title="Missing 'sub' Claim in JWT Payload",
                severity= Severity.MEDIUM,
                description="\n            The 'sub' claim is missing in the JWT payload. \n            This claim identifies the subject of the token and is typically required for authentication and authorization.",
                recommendations=["Ensure that the JWT token includes the 'sub' claim in the payload, specifying the subject of the token (e.g., user ID, email).", "Review the token generation process to include the 'sub' claim as per JWT best practices."]),

            Finding(title='Endpoint accepted token with missing subject claim.',
                    severity= Severity.HIGH,
                    description=f'The endpoint {secured_endpoint_url} returned HTTP 200 (OK)with missing subject claim in JWT token.',
                    recommendations=["Require identity-related claims such as 'sub' before authorizing requests."])
    ])

def test_analyse_results_when_endpoint_result_is_some_and_empty_sub_set_in_jwt_accepted_by_endpoint_return_expected():
    empty_sub_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIiLCJlbWFpbCI6InZhbGlkQHVzZXIudGVzdC5jby51ayIsImp0aSI6IjA3Nzk5YWNjLTNlYmYtNGFlOS1iOWRkLTNjN2VjODA1NTI3MyIsImV4cCI6MTc3NTkwNzcxMiwiaXNzIjoiSnd0VGVzdEFwaSIsImF1ZCI6Ikp3dFRlc3RBcGlVc2VycyJ9.Yiy36kKs3P_YaSkVeGTwbqp6x2E-Amhu5XjjoMEYNWc"
    token_result : TokenAnalysisResult = {
        "token": empty_sub_token,
        "is_valid_format": True,
        "segment_count": 3,
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {
            "sub": "",
            "email": "valid@user.test.co.uk",
            "jti": "07799acc-3ebf-4ae9-b9dd-3c7ec8055273",
            "exp": 1775907712,  # 11th April 2026
            "iss": "JwtTestApi",
            "aud": "JwtTestApiUsers"
        },
        "signature": None,
        "alg" : "HS256",
        "sub" : None,
        "exp" : 1775907712, # 11th April 2026
        "is_expired": False,
        "errors": [],
        "findings": [
            Finding(
                title='Symmetric JWT Algorithm Detected',
                severity=Severity.LOW,
                description='The token is using a symmetric signing algorithm (hs256). This requires secure management of the shared secret, as compromise of the secret allows full token forgery.',
                recommendations=['Ensure strong secret key management and consider using asymmetric algorithms (e.g., RS256) for better key separation between issuer and verifier.']),

            Finding(
                title="Empty 'sub' Claim in JWT Payload",
                severity=Severity.MEDIUM,
                description="\n            The empty 'sub' claim in the JWT payload. \n            This claim identifies the subject of the token and should not be empty for proper authentication and authorization.",
                recommendations=["Ensure that the 'sub' claim in the JWT payload is not empty and correctly identifies the subject of the token (e.g., user ID, email).",
                                 "Review the token generation process to ensure that the 'sub' claim is populated with meaningful information as per JWT best practices."])
        ]
    }
    endpoint_result : EndpointValidationResult =  EndpointValidationResult(
        endpoint_url= secured_endpoint_url,
        token= empty_sub_token,
        response=json.dumps(successful_json_response),
        response_json= successful_json_response,
        status_code=200,
        errors=[],
        warnings=[],
        findings=[
            Finding(
                title='Endpoint accepted token with missing subject claim.',
                severity=Severity.HIGH,
                description='The endpoint http://localhost:5000/api/profile returned HTTP 200 (OK)with missing subject claim in JWT token.',
                recommendations=["Require identity-related claims such as 'sub' before authorizing requests."])
    ])

    actual = analyse_results(token_result, endpoint_result)

    assert actual == FinalAnalysisResult(
        summary='Analysis completed with 3 finding(s). Overall severity: HIGH.',
        severity= Severity.HIGH,
        token_analysis= token_result,
        endpoint_analysis= endpoint_result,
        findings= [
            Finding(
                title='Symmetric JWT Algorithm Detected',
                severity= Severity.LOW,
                description='The token is using a symmetric signing algorithm (hs256). This requires secure management of the shared secret, as compromise of the secret allows full token forgery.',
                recommendations=['Ensure strong secret key management and consider using asymmetric algorithms (e.g., RS256) for better key separation between issuer and verifier.']),

            Finding(
                title="Empty 'sub' Claim in JWT Payload",
                severity= Severity.MEDIUM,
                description="\n            The empty 'sub' claim in the JWT payload. \n            This claim identifies the subject of the token and should not be empty for proper authentication and authorization.",
                recommendations=["Ensure that the 'sub' claim in the JWT payload is not empty and correctly identifies the subject of the token (e.g., user ID, email).",
                                 "Review the token generation process to ensure that the 'sub' claim is populated with meaningful information as per JWT best practices."]),

            Finding(
                title='Endpoint accepted token with missing subject claim.',
                severity=Severity.HIGH,
                description='The endpoint http://localhost:5000/api/profile returned HTTP 200 (OK)with missing subject claim in JWT token.',
                recommendations=["Require identity-related claims such as 'sub' before authorizing requests."])
    ])

def test_analyse_results_when_endpoint_result_is_server_side_error_500_returned_by_endpoint_return_expected():
    valid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2YWxpZEB1c2VyLnRlc3QuY28udWsiLCJlbWFpbCI6InZhbGlkQHVzZXIudGVzdC5jby51ayIsImp0aSI6IjA3Nzk5YWNjLTNlYmYtNGFlOS1iOWRkLTNjN2VjODA1NTI3MyIsImV4cCI6MTc3NTkwNzcxMiwiaXNzIjoiSnd0VGVzdEFwaSIsImF1ZCI6Ikp3dFRlc3RBcGlVc2VycyJ9.LKodA7Hw5W32FcPzrTDGNXPQpLHVMe_hNieXBwI8ZD4"
    token_result : TokenAnalysisResult = {
        "token": valid_token,
        "is_valid_format": True,
        "segment_count": 3,
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {
                  "sub": "valid@user.test.co.uk",
                  "email": "valid@user.test.co.uk",
                  "jti": "07799acc-3ebf-4ae9-b9dd-3c7ec8055273",
                  "exp": 1775907712, # 11th April 2026
                  "iss": "JwtTestApi",
                  "aud": "JwtTestApiUsers"
                },
        "signature": None,
        "alg" : "HS256",
        "sub" : "valid@user.test.co.uk",
        "exp" : 1775907712, # 11th April 2026
        "is_expired": False,
        "errors": [],
        "findings" : [
            Finding(
                title='Symmetric JWT Algorithm Detected',
                severity= Severity.LOW,
                description='The token is using a symmetric signing algorithm (hs256). This requires secure management of the shared secret, as compromise of the secret allows full token forgery.',
                recommendations=['Ensure strong secret key management and consider using asymmetric algorithms (e.g., RS256) for better key separation between issuer and verifier.'])
        ]
    }
    endpoint_result : EndpointValidationResult = EndpointValidationResult(
        endpoint_url= secured_endpoint_url,
        token= valid_token,
        response= "Internal Server Error",
        response_json= None,
        status_code=500,
        findings=[
            Finding(
                title='Endpoint returned server error',
                severity= Severity.MEDIUM,
                description='The endpoint returned HTTP 500. This may indicate weak input validation or unhandled exceptions.',
                recommendations=['Handle invalid or malformed tokens safely and return controlled 4xx responses instead of 5xx errors.'])],
        errors=['Endpoint returned a non-200 status code: 500',
                'Endpoint returned a server error status '
                'code: 500'],
        warnings=['Endpoint response is not valid JSON.']
    )

    actual = analyse_results(token_result, endpoint_result)

    assert actual == FinalAnalysisResult(
        summary='Analysis completed with 2 finding(s). Overall severity: MEDIUM.',
        severity= Severity.MEDIUM,
        token_analysis= token_result,
        endpoint_analysis= endpoint_result,
        findings= [
            Finding(
                title='Symmetric JWT Algorithm Detected',
                severity= Severity.LOW,
                description='The token is using a symmetric signing algorithm (hs256). This requires secure management of the shared secret, as compromise of the secret allows full token forgery.',
                recommendations=['Ensure strong secret key management and consider using asymmetric algorithms (e.g., RS256) for better key separation between issuer and verifier.']),

            Finding(
                title='Endpoint returned server error',
                severity= Severity.MEDIUM,
                description='The endpoint returned HTTP 500. This may indicate weak input validation or unhandled exceptions.',
                recommendations=['Handle invalid or malformed tokens safely and return controlled 4xx responses instead of 5xx errors.'])
    ])