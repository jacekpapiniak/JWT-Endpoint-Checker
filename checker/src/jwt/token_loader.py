import json # Import json for parsing JSON responses from the URL when loading token from URL
import requests # Import requests for making HTTP requests to load token from URL

from typing import Optional # Import Optional for type hinting of email and password parameters
from pathlib import Path # Import Path for file path validation
from checker.src.helpers.string_helper import is_url
from checker.src.validators.parser_validator import get_token_type # Import the function to determine the token type

def load_token(token_value: str, email: Optional[str], password: Optional[str]) -> str:
    print(f"Loading token with value: {token_value}...")
    if token_value is None or token_value == "":
        raise ValueError("Token value cannot be empty. Please provide a valid token value using the -t or --token flag.")

    token_type = get_token_type(token_value)

    if token_type == "string":
        return token_value
    elif token_type == "file":
        file_content = load_token_from_file(token_value)
        # If the file content looks like a URL, we need to make a call to that URL to get the token.
        if is_url(file_content):
            return load_token_from_url(file_content, email, password)
        else:
            return file_content
    elif token_type == "url":
        return load_token_from_url(token_value, email, password)
    else:
        raise ValueError("Invalid token value. The token value must be a raw string, a file path, or a URL.")

def load_token_from_file(token_value: str) ->    str:
    # If the token value is a file path, read the content of the file and return it as a string.
    if not Path(token_value).is_file():
        raise ValueError(f"The specified token file does not exist: {token_value}")

    with open(token_value, 'r') as file:
        content = file.read().strip() #strip() to remove any leading/trailing whitespace characters that might interfere with our URL check
        return content

def load_token_from_url(url: str, email: Optional[str], password: Optional[str]) ->  str:
    # If the token value is a URL, make a GET request to that URL and return the response as a string.

    # Make sure that we have valid URL and credentials before making the request.
    if is_url(url) is False:
        raise ValueError(f"The specified token URL is not valid: {url}")
    if email is None:
        raise ValueError("Email cannot be empty. Please provide a valid email using the -c or --credentials flag in the format email,password.")
    if password is None:
        raise ValueError("Password cannot be empty. Please provide a valid password using the -c or --credentials flag in the format email,password.")

    try:
        json = {
            "email": email,
            "password": password
        }
        response = requests.post(url, json=json) # Make a POST request to the URL with the email and password as JSON payload
        response.raise_for_status()  # Raise an exception for HTTP errors

        # The test api returns token as a JSON object with a "jwtToken" property.
        # Therefore for simplicity we assume this is the case for any URL that returns a JSON response.
        # In a real-world scenario, we would need to make this more flexible and allow the user to specify how to extract the token from the response.
        # Or we could just return the whole response and handle the token extraction in the caller code.
        # But for the sake of this example, we will assume that the response is in JSON format and contains a "jwtToken" property.
        if response.status_code is 200 and response.text.strip() != "":
            json_response = response.json() # Try to parse the response as JSON
            return json_response.get("jwtToken") # If the response is in JSON format and contains a "jwtToken" property, return its value as the token.

        # If the response failed return empty token.
        return ""

    except requests.exceptions.RequestException as e:
        raise ValueError(f"Failed to load token from URL: {e}")