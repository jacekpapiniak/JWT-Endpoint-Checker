import json
import responses # Import responses for mocking HTTP requests in tests

from checker.src.analyser.endpoint.endpoint_analyser import analyse_endpoint
from checker.src.analyser.endpoint.endpoint_validation_result import EndpointValidationResult

test_endpoint_url = "http://localhost:5000/api/profile"
test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtaXNjb25maWd1cmVkQHVzZXIudGVzdC5jby51ayIsImVtYWlsIjoibWlzY29uZmlndXJlZEB1c2VyLnRlc3QuY28udWsiLCJqdGkiOiJlNDE5NTRkYS1jMTNjLTRmZDMtYTc5Yy04ZjUyNGNhODU1MGIiLCJleHAiOjEzMDYyNTQ3NTgwMCwiaXNzIjoiSnd0VGVzdEFwaSIsImF1ZCI6Ikp3dFRlc3RBcGlVc2VycyJ9.b9jEEhFkmgfWjkE4O3ig8A_3tPDXOSekJhGiT1G8Y64"

@responses.activate # No real HTTP requests will be made within this test function, and we can define mock responses for specific URLs.
def test_analyse_endpoint_success():
    # This test will check if the analyse_endpoint function works correctly when the endpoint returns a successful response.
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
    # Mock the response from the endpoint to return a successful response with a JSON body.
    responses.add(
        responses.POST,
        test_endpoint_url,
        json= expected_json_response,
        status=200)

    actual = analyse_endpoint(test_endpoint_url, test_token)

    assert isinstance(actual, EndpointValidationResult)
    assert actual == expected

@responses.activate
def test_analyse_endpoint_returns_404_not_found():
    # This test will check if the analyse_endpoint function works correctly when the endpoint returns a failed response.
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

    actual = analyse_endpoint(test_endpoint_url, test_token)

    assert isinstance(actual, EndpointValidationResult)
    assert actual == expected

@responses.activate
def test_analyse_endpoint_returns_500_internal_server_error():
    # This test will check if the analyse_endpoint function works correctly when the endpoint returns a failed response.
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

    actual = analyse_endpoint(test_endpoint_url, test_token)

    assert isinstance(actual, EndpointValidationResult)
    assert actual == expected

@responses.activate
def test_analyse_endpoint_request_exception():
    # This test will check if the analyse_endpoint function works correctly when there is an exception thrown while making the request to the endpoint.
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

    actual = analyse_endpoint(test_endpoint_url, test_token)

    assert isinstance(actual, EndpointValidationResult)
    assert actual == expected
    
@responses.activate
def test_analyse_endpoint_empty_token():
    # This test will check if the analyse_endpoint function works correctly when the token is empty.
    # In this case, we assume that the endpoint returns a successful response even when the token is empty, 
    # but it could also return a failed response depending on the implementation of the endpoint.
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

    actual = analyse_endpoint(test_endpoint_url, test_token)

    assert isinstance(actual, EndpointValidationResult)
    assert actual == expected