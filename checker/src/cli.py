# This file is responsible for providing the command-line interface (CLI) for the JWT Endpoint Checker.
# It uses the argparse module to parse command-line arguments and provides a user-friendly interface for running the checker.
# For argparse documentation visit: https://docs.python.org/3/library/argparse.html

import argparse

def build_cli():
    parser = argparse.ArgumentParser(description="JWT Endpoint Checker CLI")
    parser = argparse.ArgumentParser(
        prog='Checker',
        description='''\
        JWT Endpoint Checker CLI - A security tool allowing for:
            - JWT Token Validation: Validate the structure and signature of JWT tokens.
            - Endpoint Testing: Test API endpoints for JWT authentication and authorization.''',
        epilog='''\
        "Examples:\n"
        "  checker -t \"eyJ...\" -w report.txt\n"
        "  checker -t token.txt -w report.txt\n"
        "  checker -t http://localhost:5000/api/login "
        "-c valid@user.test.co.uk,Password123! -w report.txt\n"
        "  checker -t \"eyJ...\" -e http://localhost:5000/api/profile "
        "-w report.txt\n"
        "  checker -t http://localhost:5000/api/login "
        "-c valid@user.test.co.uk,Password123! "
        "-e http://localhost:5000/api/profile -w report.txt"
        
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

    return parser