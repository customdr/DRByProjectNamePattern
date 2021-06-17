# Goal
Custom data retention based on custom criteria provided by configuration.

Apply different data retention criteria based on production projects vs. non-production projects. Project types are determined by project name patterns.

**By default, the script runs in dry run mode – and does not run DR. This is a fail-safe to prevent accidentally deleting data.**

*To actually run DR, they have to explicitly provide the -exec parameter.*

# Pre-Requisites
-	Powershell V5 (Ex. Windows 10 has powershell 5.1 installed). https://docs.microsoft.com/en-us/powershell/scripting/install/installing-windows-powershell?view=powershell-6
-	The custom data retention script talks to the Checkmarx database. The powershell script uses the “Invoke-SqlCmd2” module for database functionality. To install the module, execute “Install-Module -Name Invoke-SqlCmd2” in an admin powershell window.

# JSON configuration file
- The configuration file has details of the Checkmarx server (URL and service account), as well as the Checkmarx database server (Instance and optional account).
- If using SQLServer Integrated Authentication, the database account and password fields can be left empty. If explicitly using a database account (SQLServer authentication), make sure the account has access to the Checkmarx databases.
- The Checkmarx service account MUST have the following permissions (I’d recommend creating a custom role for this account in Access Control):
    - Delete Sast Scan
    - Generate Scan Report

You will need to update the relevant fields in the JSON file:
```
{
    "cx": {
        "host" : "http://UPDATE_ME",
        "username" : "UPDATE_ME",
        "password" : "UPDATE_ME",
        "db": {
            "instance": "SQLSERVERINSTANCE_UPDATE\\ME",
            "username": "",
            "password": ""
        }
    },
    "dataRetention": {
        "durationLimitHours" : 4,
        "removeScansWithNoCodeChange" : false,
        "production": {
            "projectNamePattern": "%_develop",
            "daysToRetain": 300
        },
        "other": {
            "scansToRetain": 100
        }
    }
}
```

# Powershell Data Retention Script
The dataretention.ps1 script does the following:
-	Based on criteria defined in the config file, locks scans that need to be preserved.
-	Initiates the data retention process.

# Running the Powershell Data Retention Script

Here’re the parameters that you can provide to the script:

`-exec`
Explicit flag to run the Data Retention process. If not provided, the script will default to a dry-run.

`-v`
Verbose output.

## Examples
Here’re a few example runs:

`>.\dataretention.ps1 -v `

This will run the script in dry-run mode, with verbose output.

`>.\dataretention.ps1 -v -exec`

This will execute the data retention process on the manager, with verbose output.
