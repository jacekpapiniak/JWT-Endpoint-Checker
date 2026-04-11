# This is validating the input parameters.
# For example if user provided -t/--token argument, that is an URL,
# Then we need to check if -c/--credentials argument is provided, because it is required to obtain the token from the endpoint.

from checker.src.helpers.string_helper import is_url # Import the helper function to check if a string is a URL
from pathlib import Path # Import Path for file path validation

def is_file_path(value: str) -> bool:
    # Check if the value might be a file path by looking for common file path indicators like ".txt" or "/".
    is_path = (value is not None
            and value != ""
            and (".txt" in value or "\\" in value))

    return is_path

# Function that takes the token value
# Then it analyse it and returns if it is
# A raw string, a path to a file, or a URL.
def get_token_type(token_value: str) -> str:
    # Check if the token value is a valid URL
    if is_url(token_value):
        return "url"

    # Check if the token value is a valid file path
    if is_file_path(token_value):
        #If the given token value looks like a file path, we need to check if the file actually exists.
        if(Path(token_value).is_file()):

            #if file exists, read content
            with open(token_value, 'r') as file:
                content = file.read().strip() #strip() to remove any leading/trailing whitespace characters that might interfere with our URL check
                #if file content looks like URL, return "url", otherwise return "file"
                if is_url(content):
                    return "url"
                else:
                    return "file"
        else:
            return "file"

    # If it's neither a valid URL nor a valid file path, treat it as a raw string
    return "string"

def validate_arguments(parser, args) -> None:
 # Validate command line arguments
 # The -s/--api-start and -e/--api-stop flags should not be mixed with other parameters.

  # 0. If no arguments provided,  show error.
  # vars(args) returns a dictionary of the arguments and their values.
  # values() returns a view of the values in the dictionary.
  # any() checks if there is at least one value -> Eq. C# Any() method.
  if args is None or (not any(vars(args).values())):
     parser.error('''\
     
     No arguments provided. 
     Please specify either API server control flags (-s/--api-start, -e/--api-stop) - if you wish to use our local test API server.
     Otherwise provide analysis parameters (-t/--token, -c/--credentials, -e/--endpoint, -w/--write).
     Alternatively use -h or --help for usage information.
     ''')

  # Check if the API server start/stop flags are used
  api_module = args.api_start or args.api_kill

  # Check if any of the analysis parameters are used
  analysis_module = args.token or args.credentials or args.endpoint or args.write

  # 1. API module should not be mixed with analysis module
  if api_module and analysis_module:
     parser.error('''\
         
         The API server start/stop flags (-s/--api-start and -e/--api-stop) cannot be used together
         with analysis parameters (-t/--token, -c/--credentials, -e/--endpoint, -w/--write).
         Please choose either API server control or analysis mode.
         ''')

  # 2. If credentials are provided, token endpoint must be provided.
  if args.credentials and not args.token:
     parser.error('''\
     
         The -c/--credentials argument requires the -t/--token argument to specify the endpoint for obtaining the JWT token.
         Example: checker -t \"http://localhost:5000/api/login\" -c \"email,password\" -w \"path\\report.txt\"
         ''')

  # 3. If API endpoint is provided, token must be provided.
  if args.endpoint and not args.token:
     parser.error('''\
     
         The -e/--endpoint argument requires the -t/--token argument to specify the JWT token for accessing the endpoint.
         Example: checker -t \"jwt token\" -e \"http://localhost:5000/api/profile\" -w \"path\\report.txt\"
         ''')

  # 4. If token is a URL, then credentials must be provided.
  if args.token and (get_token_type(args.token) == "url") and not args.credentials:
     parser.error('''\
         
         The -t/--token argument is a URL - to obtain the JWT token from an endpoint.
         "The login credentials -c/--credentials argument is required
         Example: checker -t \"http://localhost:5000/api/login\" -c \"email,password\" -w \"path\\report.txt\"''')

  # 5. If token is a file path, check if the file exists.
  if args.token and (get_token_type(args.token) == "file") and not Path(args.token).is_file():
     parser.error(f'''\
         The file specified in the -t/--token argument does not exist: {args.token}
         Please provide a valid file path or check the file permissions.''')

  # 6. If credentials is a file path, check if the file exists.
  if args.credentials and (get_token_type(args.credentials) == "file") and not Path(args.credentials).is_file():
        parser.error(f'''\
        The file specified in the -c/--credentials argument does not exist: {args.credentials}
        Please provide a valid file path or check the file permissions.''')