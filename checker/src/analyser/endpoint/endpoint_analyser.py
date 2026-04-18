import requests # To make HTTP requests
from checker.src.analyser.endpoint.endpoint_validation_result import EndpointValidationResult # for defining the structure of the validation result

def analyse_endpoint(endpoint_url: str, token: str) -> EndpointValidationResult:
    if not endpoint_url:
        raise ValueError("Endpoint URL is required for endpoint analysis.")
    if token is None:
        token = "" # If the token is None, we will treat it as an empty string for the purpose of endpoint analysis.

    # This is using actual class instead of a simple dictionary to store the results of the endpoint validation.
    # This allows us to have a more structured and organized way of storing the results,
    # and also makes it easier to extend the results in the future if needed.
    # It is also nice example of different approach to storing results compared to
    # the TokenAnalysisResult class that we use for storing the results of the token analysis.
    # In the TokenAnalysisResult class, we use a simple dictionary to store the results of the token analysis,
    # because the results of the token analysis are more flexible depending on the
    # structure of the token and the claims it contains.
    result = EndpointValidationResult(
        endpoint_url=endpoint_url,
        token=token if token else "",
    )

    try:
        # Our test .NET API /api/profile endpoint expects the token to be sent in
        # the json body of the request with the property name "token".
         json = {
            "token": token
         }

         # Make a POST request to the endpoint with the token as JSON payload
         response = requests.post(endpoint_url, json=json)

         result.status_code = response.status_code
         result.response = response.text

         try:
            result.response_json = response.json() # Try to parse the response as JSON
         except ValueError:
            # If the response is not in JSON format, we will add a warning to the result, but we will not consider it as an error
            # because some endpoints return non-JSON responses.
            # In a real-world scenario, we might want to make this more flexible.
            # Our test API returns JSON responses, so we will consider it as a warning if the response is not in JSON format.
            result.warnings.append("Endpoint response is not valid JSON.")

         if response.status_code != 200:
            result.errors.append(f"Endpoint returned a non-200 status code: {response.status_code}")

         if 400 <= response.status_code < 500:
            result.errors.append(f"Endpoint returned a client error status code: {response.status_code}")

         if response.status_code >= 500:
            result.errors.append(f"Endpoint returned a server error status code: {response.status_code}")

    except requests.exceptions.RequestException  as e:
       # If there was any exception thrown lets add it to the errors list of the result.
       result.errors.append(f"Failed to make a request to the endpoint: {str(e)}")

    return result