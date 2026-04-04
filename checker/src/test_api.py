# This script file is used to spin up the test .NET API server that is used for testing this CLI tool.
import json # Used to write the PID of the API server process to a file, so we can stop it later (similar to how we would use a file to store the PID in a shell script).
import subprocess # Used to run the .NET API server as a subprocess (dotnet run).
import pathlib # Used to manipulate file paths in a cross-platform way (System.IO.Path in C#).
import sys # Used to get the current working directory (System.Environment.CurrentDirectory in C#).

# Find the root of the repository that contains checker and the test API server.
# Uses the pathlib module to find the current file's path
# Then iterates over parents until it finds the folder with the name of the repository (JWT-Endpoint-Checker).
def find_repo_root():
    # The name of the root folder, from there we have access to all the files and folders in project
    top_folder_name = "JWT-Endpoint-Checker"

    # Get the current working directory (the root of the project).
    # https://docs.python.org/3/library/pathlib.html#basic-use
    current_file_path = pathlib.Path(__file__).absolute()
    print(f"Current file path: {current_file_path}")

    # Traverse up the directory tree until we find the top folder.
    for parent in current_file_path.parents:
        if parent.name == top_folder_name:
            print(f"Found repository root: {parent}")
            return parent

    print(f"Could not find repository root with name '{top_folder_name}' in the directory tree.")
    return None # If we can't find the repository root, we return None. The caller should handle this case.

def find_api_server():
 root_path = find_repo_root()
 if root_path is None:
     print("Cannot find API server because repository root could not be found.")
     return None

 # Search for the JwtTestApi.csproj file in all subfolders starting from the root path.
 # pathlib.Path.rglob() is searching for file in all directories but returns iterator,
 # So the next() is needed to get the first match (there should only be one).
 test_api_path = next(pathlib.Path(root_path).rglob("JwtTestApi.csproj"), None)
 if test_api_path is None:
     print("Could not find JwtTestApi.csproj file in the repository.")
     return None

 print(f"Found JwtTestApi.csproj file at: {test_api_path}")

 return test_api_path

def run_api_server(api_project_path):
    print("Starting API server...")
    if api_project_path is None:
        print("Cannot run API server because the project path is None.")
        return

    # Verify if the .csproj file exists at the specified path.
    if not api_project_path.is_file():
        print(f"The specified .csproj file does not exist: {api_project_path}")
        return

    # Run the .NET API server using the dotnet CLI. This will block until the server is stopped.
    # str(api_project_path) is needed because subprocess.run expects a string, and api_project_path is a pathlib.Path object.
    # this way it converts the pathlib.Path to a string that can be used in the command line.
    print(f"Running API server from project path: {api_project_path}")

    server_process = subprocess.Popen(
    ["dotnet", "run", "--project", str(api_project_path)],
    stdout=subprocess.PIPE, # Redirect the standard output to a pipe, so we can read it in Python.
    stderr=subprocess.PIPE, # Redirect the standard error to a pipe, so we can read it in Python.
    text=True,
    creationflags=subprocess.CREATE_NEW_CONSOLE) # text=True is needed to get the output as a string instead of bytes.

    print("\n\nAPI server process started. Waiting for it to be ready...\n\n")
    # Read the output from the server process and print it to the console.
    # We will look for the line that contains "Now listening on: " to get the base URL of the server.
    for line in server_process.stdout:

        # Get first line with "Now listening on: " to get the base URL of the server.
        # We also need this to see on what port the server is running (if not configured in the appsettings.json file).
        if "Now listening on:" in line:
            base_url = line.split("Now listening on: ")[1].strip() # Get the base URL from the line.
            print("=== API READY ===")
            print(f"Base URL: {base_url}")

            print("\nAvailable endpoints:")
            print(f"{base_url}/api/login")
            print(f"{base_url}/api/profile\n")

            # To stop the server we need to save PID of the process and use it to terminate the process later.
            print(f"To stop the API server, use the following command in your terminal:")
            print(f"kill {server_process.pid} # On Unix/Linux/Mac")
            print(f"taskkill /PID {server_process.pid} /F # On Windows")

            # Save the PID of the server process to a file in the json format.
            # This creates an object with a single property "pid" that contains the PID of the server process.
            pid_data = {
                "pid": server_process.pid
            }

            # Path to the file where we will save the PID of the server process, so we can stop it later.
            # We will save it in the same folder as the .csproj file, with the name PID.json.
            pid_file = pathlib.Path(f"{str(api_project_path.parent)}/PID.json")

            #Write the PID data to the file in JSON format, with indentation for readability.
            with open(pid_file, "w") as f:
                json.dump(pid_data, f, indent=4)
            break


def run_local_api_server():
    server_path = find_api_server()
    run_api_server(server_path)

def stop_api_server():
    # The PID.json file is being written in the same folder as the JwtTestApi.csproj
    # Therefore we need to find the path to that file first.
    server_path = find_api_server()
    if server_path is None:
        print("Cannot find API server because repository root could not be found.")

    # Once we have a path to the API csproj file,
    # We can search for the PID.json file in the same folder
    server_root = server_path.parent
    print("Finding PID.json file...")
    print(f"Searching for PID.json file in the folder: {str(server_root)}")
    if server_root.is_dir():
        print(f"Found directory: {str(server_root)}")
    else:
        print(f"Directory does not exist: {str(server_root)}")

    # Search for the PID.json file and get the first match (there should only be one).
    pid_file_path = next(pathlib.Path(str(server_root)).rglob("PID.json"), None)
    if pid_file_path is None:
        print("Could not find PID.json file in the repository.")

    # Verify if the PID.json file exists at the specified path.
    if not pid_file_path.is_file():
        print(f"The specified PID.json file does not exist: {pid_file_path}")
        return

    # Open the PID.json file and read the file content.
    with open(str(pid_file_path), "r") as pid_file:

        # Load the PID data from the file in json format.
        # We know that struccure of the file is like this:
        # {
        #     "pid": 12345
        # }
        pid_data = json.load(pid_file)
        pid = pid_data.get("pid") # Read the PID property from the JSON data.
        if pid is None:
            print("PID not found in PID.json file.")
            return

        print(f"Stopping API server with PID: {pid}")
        try:
            # On Unix/Linux/Mac, we can use os.kill to send a SIGTERM signal to the process.
            # On Windows, we can use subprocess.run to execute the taskkill command.
            if sys.platform.startswith("win"):
                subprocess.run(["taskkill", "/PID", str(pid), "/F"], check=True)
            else:
                import os
                os.kill(pid, 15) # 15 is the signal number for SIGTERM
            print("API server stopped successfully.")
        except Exception as e:
            print(f"Error stopping API server: {e}")

def main():
    server_path = find_api_server()
    run_api_server(server_path)


if __name__ == "__main__":
    main()