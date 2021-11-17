# Azure Migrate application credential assessment and remediation guidance

## What actions am I required to take?

You are not impacted and have no action required if you meet the following criteria:

- Azure Migrate appliance is registered after 11/02/2021 9:55 am UTC, **AND**
- Have [Appliance configuration manager version 6.1.220.1 and above](https://docs.microsoft.com/azure/migrate/migrate-appliance#check-the-appliance-services-version)

You have action if:

- Your Azure Migrate appliance was registered prior to 11/02/2021 9:55 am UTC, OR
- Your Appliance [auto-update was disabled](https://docs.microsoft.com/azure/migrate/migrate-appliance#appliance-upgrades) **and** registered after 11/02/2021 9:55 am UTC

Proceed to the assessment and mitigation steps below.

## Assessment script

The assessment script can help identify the Azure Migrate resources associated with the impacted Azure AD applications so that you can perform the required remediation steps. **You can run the script from any Windows server with internet connectivity**. Before executing the script, make sure you have met the following prerequisites:

### Prerequisites

1. Windows PowerShell version 5.1 or later installed.
2. .NET framework 4.7.2 or later installed.
3. The following URLs accessible from the server:

Azure public cloud URLs

- `*.powershellgallery.com`
- `login.microsoftonline.com`
- `graph.windows.net`
- `management.azure.com`
- `*.azureedge.net`
- `aadcdn.msftauth.net`
- `aadcdn.msftauthimages.net`
- `dc.services.visualstudio.com`
- `aka.ms\*`
- `download.microsoft.com/download`
- `go.microsoft.com/*`
  
    If there is a proxy server blocking access to these URLs, then update the proxy details to the system configuration before executing the script.

4. You need the following permissions on the Azure user account:

- Application.Read permission at tenant level to enumerate the impacted Azure AD applications
- ‘Contributor’ access on the Azure subscription(s) to enumerate the Azure Migrate resources associated with the impacted Azure AD application(s).

### Execution instructions

1. Log in to any Windows server with internet connectivity.
2. Download zip file under at [https://aka.ms/azuremigrateimpactassessment](https://aka.ms/azuremigrateimpactassessment).
3. Open Windows PowerShell as an Administrator.
4. Change the folder path to the location where the file were downloaded. 
5. Execute the script in one of the following ways:

   - By providing the -AppId parameter to enumerate the details of Azure Migrate resources associated with the impacted AAD App: `.\ AssessAzMigrateApps.ps1 -TenantId <Tenant ID> -AppId <Application ID>`
   - By providing the -ScanAll parameter to enumerate all impacted Azure AD applications in the tenant and their associated Azure Migrate resource details: `.\ AssessAzMigrateApps.ps1 -TenantId <Tenant ID> -ScanAll`

6. When prompted, log in with your Azure user account. The user account should have permissions listed in prerequisites above.
7. The script will generate an assessment report with the details of the impacted Azure AD applications and associated Azure Migrate resources.

### What the assessment script does

Running the command- `.\ AssessAzMigrateApps.ps1 -TenantId <Tenant ID> -AppId <Application ID>` does the following:

1. Checks if the Application ID provided in -AppId parameter is impacted
2. Finds the Azure Migrate resources associated with the impacted Azure AD application
3. Generates an assessment report with details of the associated Azure Migrate resources so that you can perform the remediation steps

Running the command- `.\ AssessAzMigrateApps.ps1 -TenantId <Tenant ID> -ScanAll` does the following:

1. Connects to the tenant ID provided in the command using the Azure account, user provides to log in through the script.
2. Scans and finds all the impacted Azure AD applications with the unprotected private key.
3. Identifies the impacted Azure AD applications, associated with Azure Migrate.
4. Finds the Azure Migrate resources accessible to the currently logged in user across subscriptions within the tenant.
5. Maps the impacted Azure Migrate resources information to the impacted Azure AD applications found in Step 3.
6. Generates an assessment report with the information of the impacted Azure AD applications with the details of the associated Azure Migrate resources.

### Assessment report

The assessment report generated by the script will have the following columns:

|No|Column name | Description|
|--|--|--|
|1|Azure AD application name| Provides the names of the impacted Azure AD application(s) associated with Azure Migrate, containing one of the following suffixes:`resourceaccessaadapp`,`agentauthaadapp`,`authandaccessaadapp`|
|2|Azure AD application owner | Provides the email address of the Azure AD application owner|
|3|Azure AD application ID|Provides the ID of the impacted Azure AD application(s)|
|4|User access to associated Migrate resources|Shows if the currently logged in user has access to the associated Azure Migrate resources across subscriptions in the tenant|
|5|Subscription ID|Provides the IDs of subscriptions where the currently logged in user could access the Azure Migrate resources|
|6|Resource Group|Provides the name of the Resource Group where the Azure Migrate resources were created|
|7|Azure Migrate project name|Provides the name of the Azure Migrate project where the Azure Migrate appliance(s) were registered|
|8|Azure Migrate appliance name|Provides the name of the Azure Migrate appliance which created the impacted Azure AD application during its registration|
|9|Scenario|Provides the scenario of the appliance deployed-VMware/Hyper-V/Physical or other clouds|
|10|Appliance activity status (last 30 days)|Provides the information on whether the appliance was active in the last 30 days (agents sent heartbeat to Azure Migrate services)|
|11|Appliance server hostname|Provides the hostname of the server where the appliance was deployed.(This may have changed over time in your on-premises environment)|

### Recommendations

Based on the information that you could pull from the script in the context of the currently logged in user, we recommend you perform one of the following steps:

1. If the value in column 4 (User access to associated Migrate resources) shows ‘Not accessible’, it can be due to one of the following reasons:
   - You do not have the required permissions (as stated in prerequisites above) on the subscription to enumerate information for Azure Migrate resources associated with the impacted Azure AD application(s).
   - The Azure Migrate resources associated with the impacted Azure AD application may have been deleted.
2. For cases where Azure Migrate resources have been deleted or there are inactive Azure Migrate appliances that you do not intend to use in future, you can delete the impacted Azure AD application(s).
3. For active Azure Migrate appliances that you intend to use in future, you need to rotate the certificates on the impacted Azure AD Applications by running the mitigation script on each of the appliance servers (server hostname provided in the assessment report).

## Mitigation script

For the impacted Azure AD application(s), you need to execute the mitigation script on each Azure Migrate appliance in your environment). Before executing the script, make sure you have met the following prerequisites:

### Mitigation Prerequisites

1. Windows PowerShell version 5.1 or later installed.
2. Windows PowerShell running 64-bit version.
3. .NET framework 4.7.2 or later installed.
4. The following URLs accessible from the server (In addition to the other [URLs](https://docs.microsoft.com/azure/migrate/migrate-appliance#public-cloud-urls) that you would have already whitelisted for the appliance registration):

**Azure public cloud URLs**

- *.powershellgallery.com
- *.azureedge.net
- aadcdn.msftauthimages.net
  
    If there is a proxy server configured on the appliance configuration manager, then update the proxy details to the system configuration before executing the script.

5. You need the following permissions on the Azure user account:
   - `Contributor` access on the Azure subscription that has the Azure Migrate project the appliance is registered to, and
   - Owner permissions on the impacted Azure AD Application(s).
6. For appliances deployed to perform agentless replication of VMware VMs, if you have started replication for the first time in the project from portal, we recommend that you wait for 5 minutes for the ‘Associate replication policy’ job to complete before you can execute the script.

### Mitigation execution instructions

1. To run the script, you need to log in to the server hosting the Azure Migrate appliance.
2. Download zip files at  [https://aka.ms/azuremigratecertrotation](https://aka.ms/azuremigratecertrotation)
3. Open Windows PowerShell as an Administrator.
4. Change the folder path to the location where the files were downloaded.
5. Execute the script by running the following command: `.\ AzureMigrateRotateCertificate.ps1`
6. When prompted, log in with your Azure user account. The user account should have permissions listed in prerequisites.
7. Wait for the script to execute successfully.

### What the mitigation script does

1. Fetches Key Vault name, certificate name and AAD App ID from Azure Migrate zip file Hub/configuration files on appliance server. 
2. Deletes old certificate present in KV and creates a new certificate with the same name.
3. Imports the certificate to appliance server in PFX format.
4. Deletes the old certificate in the impacted AAD App which removes the vulnerability of the private key misuse.
5. Attaches the public key of the certificate (CER format) that was generated in Step 2 to the AAD app.
6. Updates the Azure Migrate appliance software configuration files on appliance to use the new certificate and restarts the Azure Migrate appliance agents.