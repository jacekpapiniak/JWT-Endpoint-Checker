from .jwt import token_analyser # Import the token analyser module to perform analysis on the loaded JWT token
from .cli.cli import build_cli # Import the argpars
from .validators.parser_validator import validate_arguments # Import the function to validate command line arguments
from .test_api import run_local_api_server, stop_api_server # Import the function to run the local API server
from .jwt import token_loader, token_analyser # Import the token loader module to handle token loading from string, file, or URL
from checker.src.jwt.token_analysis_result import TokenAnalysisResult # for defining the structure of the analysis result
from checker.src.endpoint.endpoint_analyser import analyse_endpoint
from checker.src.endpoint.endpoint_validation_result import EndpointValidationResult
from datetime import datetime, timezone # for converting the exp claim to a human-readable format

def main():
    cli_parser = build_cli()

    # Read the command line arguments
    args = cli_parser.parse_args()

    # Validate the command line arguments
    validate_arguments(cli_parser, args)

    if args.api_start:
        run_local_api_server()
        return

    if args.api_kill:
        print("Stopping API server...")
        # We need to stop the API server that we started with the --api-start flag.
        # However, since the API server is started in a separate process,
        # we need to keep track of that process in order to stop it later.
        stop_api_server()
        return

    token : str
    token_analysis_result : TokenAnalysisResult
    endpoint_analysis_result : EndpointValidationResult

    if args.token:
        print("Loading token...")
        # The credentials are in format "email,password".
        # Therefore we can use split(",") to get the email and password as separate values.
        if args.credentials:
            email, password = args.credentials.split(",")
        else:
            email, password = None, None

        token = token_loader.load_token(args.token, email, password)
        print(f"Token loaded successfully: {token}")
        token_analysis_result = token_analyser.analyse_token(token, int(datetime.now(timezone.utc).timestamp()))
        print("Token analysis result:")
        print(token_analysis_result)

    if args.endpoint:
        print("Testing endpoint...")
        # We need to test the endpoint with the JWT token that we loaded.
        # The endpoint should be provided as a URL, for example: http://localhost:5000/api/profile.
        # We will use the token_analysis_result to get the token and test the endpoint with it.
        # The result of the endpoint testing will be saved in the report.txt file.
        # The report will contain the results of:
        # - JWT token validation: Information about the validity of the token, its structure, and claims.
        # - Endpoint testing: Information about the accessibility of the endpoint, the response status code.
        endpoint_analysis_result = analyse_endpoint(args.endpoint, token)
        print("Endpoint analysis result:")
        print(endpoint_analysis_result)
    else:
        print("No action specified. Use -h or --help for usage information.")

if __name__ == "__main__":
    main()