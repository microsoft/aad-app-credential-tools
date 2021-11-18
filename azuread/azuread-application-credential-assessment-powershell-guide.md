# KeyCredential assessment PowerShell module for MS Graph API

Run the Azure AD App credential key scanner PowerShell module to find out if credential(s) of an application or service principal need to be rotated.
This module calls the MS Graph application API and reads the `hasExtendedValue` property as described in the '**Use MS Graph API**' assessment section.

We recommend importing the module each time you run it, to make sure you are working with the latest version of the script.

## Required parameters

| **Parameter** |**Description**|
|---|---|
|-TenantId| The tenant id to search in.|
|-ObjectClass| Type of objects to search. Possible values are `Application` or `ServicePrincipal`.|

## Optional parameters

| **Parameter** |**Description**|
|---|---|
|-ScanAll| Flag that enables the module to scan all application or service principal objects in a tenant.|
|-Env| The cloud environment (Default: **AzureCloud**). Other possible options are '*AzureUSGovernment*' and '*AzureChinaCloud*'|
|-AppId| The GUID of the application's or service principal's AppId for which the credentials need to be assessed.|
|-ObjectId| The GUID value of the application's or service principal's objectId for which the credentials need to be assessed.|
|-SkipTokenUrl| If list all application/servicePrincipals request fails during the middle for any reason, a URL containing $skipToken will be outputted in console. Copy the url and re-run the module with -SkipTokenUrl <url> to continue from the page where the api request last failed.|
|-ExtendedOutputSchema| Toggle to get more information about each application/service principal. Additional columns included as part of this flag: "ObjectCreatedDateTime", "CreatedOnBehalfOf", "Owners", "AppIdentifierUri", "SignInAudience", "HomePageUrl".|
|<img width=200/>|<img width=500/>|

> [!NOTE]
> If ExtendedOutputSchema is toggled, then the pageSize is fixed to 100 and the request will take longer to run.

## Advance parameters

| **Parameter** |**Description**|
|---|---|
|-PageSize| The size of each page returned per MS graph request (aka the value for $top. 200 by default).|
|-SleepInterval| The sleep duration in seconds between the paginated MS graph requests (2 by default).|
|-MaxRetryLimit| The maximum number of retries if MS Graph returns 429. (3 by default).|
|-MaxPageSize| The maximum limit for PageSize (500 by default).|
|<img width=200/>|<img width=500/>|

## Examples

| Module option                              | Sample request |
| -------------------------------------------- | -------------------------------------------- |
|<img width=300/>|<img width=500/>|
| Install module|`Install-Module -Name AffectedKeyCredentials`|
| Import module|`Import-Module AffectedKeyCredentials.psm1 [-Force]`|
| Scan a single application (by appId)|`Get-AffectedKeyCredentials -TenantId 714f1975-81e3-4d98-9cb9-c602b0d0d3c8 -ObjectClass Application -AppId 1e918ef4-00b2-45c7-897f-e5fc097709bd`|
| Scan a single application (by objectId)|`Get-AffectedKeyCredentials -TenantId 714f1975-81e3-4d98-9cb9-c602b0d0d3c8 -ObjectClass Application -ObjectId a8b9d4d4-5a21-497e-917b-4f6b0833456f`|
| Scan a single service principal (by appPrincipalId)|`Get-AffectedKeyCredentials -TenantId 714f1975-81e3-4d98-9cb9-c602b0d0d3c8 -ObjectClass ServicePrincipal -AppId1e918ef4-00b2-45c7-897f-e5fc097709bd`|
| Scan a single service principal (by objectId)|`Get-AffectedKeyCredentials -TenantId 714f1975-81e3-4d98-9cb9-c602b0d0d3c8 -ObjectClass ServicePrincipal -ObjectId a8b9d4d4-5a21-497e-917b-4f6b0833456f`|
| Scan all application|`Get-AffectedKeyCredentials -TenantId 714f1975-81e3-4d98-9cb9-c602b0d0d3c8 -ObjectClass Application -ScanAll`|
| Scan all service principals|`Get-AffectedKeyCredentials -TenantId 714f1975-81e3-4d98-9cb9-c602b0d0d3c8 -ObjectClass ServicePrincipal -ScanAll`|
| Scan all applications and store as .csv|`Get-AffectedKeyCredentials -TenantId 714f1975-81e3-4d98-9cb9-c602b0d0d3c8 -ObjectClass Application -ScanAll \| export-csv -Path 'outputFilePath/outputFile.csv'-NoTypeInformation`|
| Scan all applications and store as .json|`Get-AffectedKeyCredentials -TenantId 714f1975-81e3-4d98-9cb9-c602b0d0d3c8 -ObjectClass Application -ScanAll \| ConvertTo-Json \| Out-File 'outputFilePath/outputFilejson'`|
| Scan in other cloud environments|`Get-AffectedKeyCredentials -TenantId 714f1975-81e3-4d98-9cb9-c602b0d0d3c8 -ObjectClass ServicePrincipal -Env 'AzureUSGovernment'`|
| Scan with a SkipTokenURL|`Get-AffectedKeyCredentials -TenantId 714f1975-81e3-4d98-9cb9-c602b0d0d3c8 -ObjectClass ServicePrincipal -SkipTokenUrl 'https://graph.microsoft.com/beta/myorganizationserviceprincipals?$skiptoken=RFNwdAIAAQAAADVTZXJ2aWNlUHJpbmNpcGFsXzUxNTdhNWYxLTVmZDItNDE5Ny1hNWNkLTkyOTY5Y2M5OTBjNTVTZXJ2aWNlUHJpbmNpcGFsXzUxNTdhNWYxLTVmZDItNDE5Ny1hNWNkLTkyOTY5Y2M5OTBjNQAAAAAAAAAAAAAA'`|
| Scan with extended schema|`Get-AffectedKeyCredentials -TenantId 714f1975-81e3-4d98-9cb9-c602b0d0d3c8 -ObjectClass Application -ExtendedOutputSchema`|
| Scan in Verbose mode (extra console logging for troubleshooting)|`Get-AffectedKeyCredentials -TenantId 714f1975-81e3-4d98-9cb9-c602b0d0d3c8 -ObjectClass ServicePrincipal -Verbose`|

## Additional info

You can find more details about the module in the [PowerShell Gallery](https://www.powershellgallery.com/packages/AffectedKeyCredentials).
