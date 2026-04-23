import json
import responses # Import responses for mocking HTTP requests in tests

from checker.src.analyser.finding import Finding
from checker.src.common.severity import Severity
from checker.src.analyser.jwt.token_analysis_result import TokenAnalysisResult
from checker.src.analyser.endpoint.endpoint_analyser import record_endpoint_behaviour, analyse_endpoint
from checker.src.analyser.endpoint.endpoint_validation_result import EndpointValidationResult

test_endpoint_url = "http://localhost:5000/api/profile"
test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtaXNjb25maWd1cmVkQHVzZXIudGVzdC5jby51ayIsImVtYWlsIjoibWlzY29uZmlndXJlZEB1c2VyLnRlc3QuY28udWsiLCJqdGkiOiJlNDE5NTRkYS1jMTNjLTRmZDMtYTc5Yy04ZjUyNGNhODU1MGIiLCJleHAiOjEzMDYyNTQ3NTgwMCwiaXNzIjoiSnd0VGVzdEFwaSIsImF1ZCI6Ikp3dFRlc3RBcGlVc2VycyJ9.b9jEEhFkmgfWjkE4O3ig8A_3tPDXOSekJhGiT1G8Y64"
successful_json_response = {
    "name": "Valid User",
    "email": "valid@user.test.co.uk",
    "role": "Student"
}

@responses.activate # No real HTTP requests will be made within this test function, and we can define mock responses for specific URLs.
def test_record_endpoint_behaviour_success():
    # This test will check if the record_endpoint_behaviour function works correctly when the endpoint returns a successful response.
    init = EndpointValidationResult(
        endpoint_url=test_endpoint_url,
        token=test_token if test_token else "")

    expected = EndpointValidationResult(
        endpoint_url=test_endpoint_url,
        token=test_token if test_token else "",
        response=json.dumps(successful_json_response),
        response_json= successful_json_response,
        status_code=200
    )
    # Mock the response from the endpoint to return a successful response with a JSON body.
    responses.add(
        responses.POST,
        test_endpoint_url,
        json= successful_json_response,
        status=200)

    actual = record_endpoint_behaviour(test_endpoint_url, test_token, init)

    assert isinstance(actual, EndpointValidationResult)
    assert actual == expected

@responses.activate
def test_record_endpoint_behaviour_returns_404_not_found():
    # This test will check if the record_endpoint_behaviour function works correctly when the endpoint returns a failed response.
    init = EndpointValidationResult(
        endpoint_url=test_endpoint_url,
        token=test_token if test_token else "")
    
    expected = EndpointValidationResult(
        endpoint_url=test_endpoint_url,
        token=test_token if test_token else "",
        response="Not Found",
        response_json=None,
        status_code=404,
        errors=["Endpoint returned a non-200 status code: 404", "Endpoint returned a client error status code: 404"],
        warnings=["Endpoint response is not valid JSON."]
    )
    # Mock the response from the endpoint to return a failed response with a non-JSON body.
    responses.add(
        responses.POST,
        test_endpoint_url,
        body="Not Found",
        status=404)

    actual = record_endpoint_behaviour(test_endpoint_url, test_token, init)

    assert isinstance(actual, EndpointValidationResult)
    assert actual == expected

@responses.activate
def test_record_endpoint_behaviour_returns_500_internal_server_error():
    # This test will check if the record_endpoint_behaviour function works correctly when the endpoint returns a failed response.
    init = EndpointValidationResult(
        endpoint_url=test_endpoint_url,
        token=test_token if test_token else "")
    
    expected = EndpointValidationResult(
        endpoint_url=test_endpoint_url,
        token=test_token if test_token else "",
        response="Internal Server Error",
        response_json=None,
        status_code=500,
        errors=["Endpoint returned a non-200 status code: 500", "Endpoint returned a server error status code: 500"],
        warnings=["Endpoint response is not valid JSON."]
    )
    # Mock the response from the endpoint to return a failed response with a non-JSON body.
    responses.add(
        responses.POST,
        test_endpoint_url,
        body="Internal Server Error",
        status=500)

    actual = record_endpoint_behaviour(test_endpoint_url, test_token, init)

    assert isinstance(actual, EndpointValidationResult)
    assert actual == expected

@responses.activate
def test_record_endpoint_behaviour_request_exception():
    # This test will check if the record_endpoint_behaviour function works correctly when there is an exception thrown while making the request to the endpoint.
    init = EndpointValidationResult(
        endpoint_url=test_endpoint_url,
        token=test_token if test_token else "")

    expected = EndpointValidationResult(
        endpoint_url=test_endpoint_url,
        token=test_token if test_token else "",
        response="",
        response_json=None,
        status_code=0,
        errors=["Failed to make a request to the endpoint: Failed to establish a new connection: Connection refused"]
    )
    # Mock the response from the endpoint to raise a ConnectionError when trying to make a request to it.
    responses.add(
        responses.POST,
        test_endpoint_url,
        body=responses.ConnectionError("Failed to establish a new connection: Connection refused"))

    actual = record_endpoint_behaviour(test_endpoint_url, test_token, init)

    assert isinstance(actual, EndpointValidationResult)
    assert actual == expected
    
@responses.activate
def test_record_endpoint_behaviour_empty_token():
    # This test will check if the record_endpoint_behaviour function works correctly when the token is empty.
    # In this case, we assume that the endpoint returns a successful response even when the token is empty, 
    # but it could also return a failed response depending on the implementation of the endpoint.
    init = EndpointValidationResult(
        endpoint_url=test_endpoint_url,
        token=test_token if test_token else "")

    expected_json_response = {
              "name": "Valid User",
              "email": "valid@user.test.co.uk",
              "role": "Student"
            }
    expected = EndpointValidationResult(
        endpoint_url=test_endpoint_url,
        token=test_token if test_token else "",
        response=json.dumps(expected_json_response),
        response_json= expected_json_response,
        status_code=200
    )

    responses.add(
        responses.POST,
        test_endpoint_url,
        json=expected_json_response,
        status=200)

    actual = record_endpoint_behaviour(test_endpoint_url, test_token, init)

    assert isinstance(actual, EndpointValidationResult)
    assert actual == expected

@responses.activate
def test_analyse_endpoint_when_endpoint_result_is_some_and_malformed_jwt_accepted_by_endpoint_return_expected():
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

    # Mock the response from the endpoint to return a successful response with a JSON body.
    responses.add(
        responses.POST,
        test_endpoint_url,
        json= successful_json_response,
        status=200)

    actual = analyse_endpoint(test_endpoint_url, token_result)

    assert actual == EndpointValidationResult(
        endpoint_url=test_endpoint_url,
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
                description='The endpoint http://localhost:5000/api/profile returned HTTP 200 (OK)with JWT token with invalid format.',
                recommendations=['Ensure that JWT toke structure is validated by the endpoint before processing authorization.']),

            Finding(
                title='Endpoint accepted token with missing subject claim.',
                severity=Severity.HIGH,
                description='The endpoint http://localhost:5000/api/profile returned HTTP 200 (OK)with missing subject claim in JWT token.',
                recommendations=["Require identity-related claims such as 'sub' before authorizing requests."])
        ])

@responses.activate
def test_analyse_endpoint_when_endpoint_result_is_some_and_expired_jwt_accepted_by_endpoint_return_expected():
    expired_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2YWxpZEB1c2VyLnRlc3QuY28udWsiLCJlbWFpbCI6InZhbGlkQHVzZXIudGVzdC5jby51ayIsImp0aSI6IjA3Nzk5YWNjLTNlYmYtNGFlOS1iOWRkLTNjN2VjODA1NTI3MyIsImV4cCI6MTc3NTkwNzcxMiwiaXNzIjoiSnd0VGVzdEFwaSIsImF1ZCI6Ikp3dFRlc3RBcGlVc2VycyJ9.LKodA7Hw5W32FcPzrTDGNXPQpLHVMe_hNieXBwI8ZD4"
    token_result: TokenAnalysisResult = {
        "token": expired_token,
        "is_valid_format": True,
        "segment_count": 3,
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": {
            "sub": "valid@user.test.co.uk",
            "email": "valid@user.test.co.uk",
            "jti": "07799acc-3ebf-4ae9-b9dd-3c7ec8055273",
            "exp": 1775907712,  # 11th April 2026
            "iss": "JwtTestApi",
            "aud": "JwtTestApiUsers"
        },
        "signature": None,
        "alg": "HS256",
        "sub": "valid@user.test.co.uk",
        "exp": 1775907712,  # 11th April 2026
        "is_expired": True,
        "errors": [],
        "findings": [
            Finding(
                title='Symmetric JWT Algorithm Detected',
                severity=Severity.LOW,
                description='The token is using a symmetric signing algorithm (hs256). '
                            'This requires secure management of the shared secret, as compromise of the secret allows full token forgery.',
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
    responses.add(
        responses.POST,
        test_endpoint_url,
        json= successful_json_response,
        status=200)

    actual = analyse_endpoint(test_endpoint_url, token_result)

    assert actual == EndpointValidationResult(
        endpoint_url= test_endpoint_url,
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
                description='The endpoint http://localhost:5000/api/profile returned HTTP 200 (OK)with expired JWT token.',
                recommendations=['Ensure that endpoint validates JWT tokens expiration.']
        )])

@responses.activate
def test_analyse_endpoint_when_endpoint_result_is_some_and_no_sub_set_in_jwt_accepted_by_endpoint_return_expected():
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
             description='The token is using a symmetric signing algorithm (hs256). '
                         'This requires secure management of the shared secret, as compromise of the secret allows full token forgery.',
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
    responses.add(
        responses.POST,
        test_endpoint_url,
        json= successful_json_response,
        status=200)

    actual = analyse_endpoint(test_endpoint_url, token_result)

    assert actual == EndpointValidationResult(
        endpoint_url= test_endpoint_url,
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
                description='The endpoint http://localhost:5000/api/profile returned HTTP 200 (OK)with missing subject claim in JWT token.',
                recommendations=["Require identity-related claims such as 'sub' before authorizing requests."])
    ])

@responses.activate
def test_analyse_endpoint_when_endpoint_result_is_some_and_empty_sub_set_in_jwt_accepted_by_endpoint_return_expected():
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
                description='The token is using a symmetric signing algorithm (hs256). '
                            'This requires secure management of the shared secret, as compromise of the secret allows full token forgery.',
                recommendations=['Ensure strong secret key management and consider using asymmetric algorithms (e.g., RS256) for better key separation between issuer and verifier.']),

            Finding(
                title="Empty 'sub' Claim in JWT Payload",
                severity=Severity.MEDIUM,
                description="\n            The empty 'sub' claim in the JWT payload. \n            This claim identifies the subject of the token and should not be empty for proper authentication and authorization.",
                recommendations=["Ensure that the 'sub' claim in the JWT payload is not empty and correctly identifies the subject of the token (e.g., user ID, email).",
                                 "Review the token generation process to ensure that the 'sub' claim is populated with meaningful information as per JWT best practices."])
        ]
    }
    responses.add(
        responses.POST,
        test_endpoint_url,
        json= successful_json_response,
        status=200)


    actual = analyse_endpoint(test_endpoint_url, token_result)

    assert actual == EndpointValidationResult(
        endpoint_url= test_endpoint_url,
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

@responses.activate
def test_analyse_endpoint_endpoint_result_is_server_side_error_500_returned_by_endpoint_return_expected():
    token_result : TokenAnalysisResult = {
        "token": test_token,
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
                description='The token is using a symmetric signing algorithm (hs256). '
                            'This requires secure management of the shared secret, as compromise of the secret allows full token forgery.',
                recommendations=['Ensure strong secret key management and consider using asymmetric algorithms (e.g., RS256) for better key separation between issuer and verifier.'])
        ]
    }
    responses.add(
        responses.POST,
        test_endpoint_url,
        body="Internal Server Error",
        status=500)

    actual = analyse_endpoint(test_endpoint_url, token_result)

    assert actual == EndpointValidationResult(
        endpoint_url= test_endpoint_url,
        token= test_token,
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
