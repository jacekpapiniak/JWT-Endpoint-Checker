# This file is responsible for providing the command-line interface (CLI) for the JWT Endpoint Checker.
# It uses the argparse module to parse command-line arguments and provides a user-friendly interface for running the checker.
# For argparse documentation visit: https://docs.python.org/3/library/argparse.html

import argparse
from typing import Required

def build_cli():
    parser = argparse.ArgumentParser(
        prog='Checker',
        description='''\
        
        
        JWT Endpoint Checker CLI - A security tool allowing for:
            
            - JWT Token Validation: Validate the structure and signature of JWT tokens.
            - Endpoint Testing: Test API endpoints for JWT authentication and authorization.
            
            ''',

        epilog='''\
        Examples:\n
          checker -t \"<text-or-path>\" -w \"<path/report.txt>\" \n
          checker -t \"http://localhost:5000/api/login\" -c \"valid@user.test.co.uk,Password123!\" -w report.txt\n
          checker -t \"<text-or-path>\" -e \"http://localhost:5000/api/profile\" -w \"<path/report.txt>\" \n
          checker -t \"http://localhost:5000/api/login\" -c \"valid@user.test.co.uk,Password123!\" -e \"http://localhost:5000/api/profile\" -w \"report.txt\"
        
        \nFor more information, visit the GitHub repository: https://github.com/jacekpapiniak/JWT-Endpoint-Checker''',
    formatter_class = argparse.RawTextHelpFormatter
    )

    # Add arguments for the CLI
    parser.add_argument(
        "-strt", "--api-start",
        action="store_true", # This means that if the flag is present, the value will be True, otherwise it will be False. This is useful for flags that don't require a value, like --api-start.
        help="Start local API"
    )

    # Add arguments for the CLI
    parser.add_argument(
        "-stp", "--api-stop",
        action="store_true", # This means that if the flag is present, the value will be True, otherwise it will be False. This is useful for flags that don't require a value, like --api-start.
        help="Stop local API"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output for debugging purposes"
    )
    
    # This sections arguments are related to the JWT token input.
    parser.add_argument(
        "-t", "--token",
        type=str,
        help='''\
        This argument declares the source of the JWT token to be checked. It can be provided in three ways:
        1. As a string: Provide the JWT token directly in the command line
            
            Example:
            checker -t \"eyJhbGciOi...\" -w \"path\\report.txt\"
            
            Provides the JWT token as a string parameter.
            Result of the analysis will be saved in the report.txt file.
            
        
        2. As a path to a file.
        
            Example:
            checker -t \"path\\token.txt\" -w \"path\\report.txt\"
            
            Provides the JWT token as a path to the file that contains the token. 
            The file should contain only the token, without any additional text or formatting.
            The result of the analysis will be saved in the report.txt file.
            
        3. As a URL to an endpoint that returns a JWT token in the response.
                    
            Example:
            checker -t \"http://localhost:5000/api/login\" -c \"email,password\"  -w \"path\\report.txt\" 
            
            Provides the JWT token as a URL to an endpoint that returns a JWT token in the response.
            The credentials for obtaining the token should be provided with the -c or --credentials flag.
            Credentials format 'username,password' or as a path to a file containing the credentials in the same format.
            If the JWT token is successfully obtained from the endpoint, it will be analyzed.
            The result will be saved in the report.txt file.
        '''
    )

    parser.add_argument(
        "-c", "--credentials",
        type=str,
        help='''\
            Credentials for obtaining JWT token from an endpoint.
            Expected format 'username,password'.
            
            The credentials can be provided in two ways:
            1. As a string: Provide the credentials directly in the command line
            
                Example:
                checker -t \"http://localhost:5000/api/login\" -c \"email,password\"  -w \"path\\report.txt\"
                Provides the credentials as a string parameter.
                The JWT token will be obtained from the specified endpoint using these credentials.
                The result of the analysis will be saved in the report.txt file.
                
            2. As a path to a file.
            
                Example:
                checker -t \"http://localhost:5000/api/login\" -c \"path\\credentials.txt\"  -w \"path\\report.txt\"
                Provides the credentials as a path to a file that contains the credentials in the expected format.
                The JWT token will be obtained from the specified endpoint using these credentials.
                The result of the analysis will be saved in the report.txt file.
        '''
    )

    parser.add_argument(
        "-w", "--write",
        type=str,
        help='''\
        Path to a file where the report will be saved.
        The report will contain the results of:
        - JWT token validation: Information about the validity of the token, its structure, and claims.
        - Endpoint testing: Information about the accessibility of the endpoint, the response status code.
        '''
    )

    parser.add_argument(
        "-e", "--endpoint",
        type=str,
        help='''\
        API endpoint to test with the JWT token.
        The endpoint should be provided as a URL, for example: http://localhost:5000/api/profile.
        
        Thet checker will attempt to access the specified endpoint using the:
         - JWT token provided with the -t or --token flag
        
        Example:
        checker -t \"http://localhost:5000/api/login\" -c \"email,password\"  -e \"http://localhost:5000/api/profile\" -w \"path\\report.txt\"
        
        Provides the endpoint to test with the JWT token obtained from the login endpoint.
        The result of the analysis will be saved in the report.txt file.
        '''
    )

    return parser