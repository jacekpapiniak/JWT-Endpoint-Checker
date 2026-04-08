from .cli import build_cli # Import the argpars
from .validators.parser_validator import validate_arguments # Import the function to validate command line arguments
from .test_api import run_local_api_server, stop_api_server # Import the function to run the local API server

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

    print("No action specified. Use -h or --help for usage information.")

if __name__ == "__main__":
    main()