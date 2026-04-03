# How to run test .NET API Server

## .NET API Server appsettings.json
To configure the .NET API Server, you need to set up the `appsettings.json` file with the appropriate settings. 
Please use available in repo `appsettings.template.json` file as a template and update as needed.

To run the test .NET API Server, follow these steps:
1. Open a terminal and navigate to the `checker/src/` directory.
2. Run the following command to start the server: `python runTestApi.py`
3. The server will start and listen for incoming requests. You can test the API endpoints using existing Bruno collections.