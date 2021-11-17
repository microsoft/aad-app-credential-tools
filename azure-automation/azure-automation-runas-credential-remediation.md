# Azure Automation application credential assessment and remediation guidance

## Disclaimer

Guidance in this document applies only in relation to the mitigation steps necessary for the issue disclosed in the [CVE](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42306) and detailed in [Microsoft Security Response Center blog](https://aka.ms/CVE-2021-42306-AAD). Do not use this guidance as general credential rotation procedure.

This script is used to check which automation accounts are impacted by CVE-2021-42306 and for each impacted account, it allows the user to remediate the issue.

## Details

CVE-2021-42306 has more details about the issue regarding the Azure-AD key credentials. This script will assess automation account which has configured RunAs accounts and checks if the corresponding AAD application is impacted or not. If it is impacted, on confirmation it will renew the key credentials of Azure-AD App by deleting the older certificate(s) and uploading new self-signed certificate to the Azure-AD App, which will mitigate the issue.

## Usage

 The script can be used to run at a time on single AAD App( belong to automation) or set of subscriptions. Please note that the script will work for Automation managed RunAs AAD Apps, and if you are using Third-party/CA-signed certificates, please follow manual mitigation steps mentioned below

***It is highly recommended to try with single AppID option or try with single subscription which is having not more than one Automation account.***

## Important Notes

***1. If the runbooks uses RunAs Azure-AD App to access the resources through Az/AzureRM cmdlets, access-tokens will become invalid due to certificate changes, and so jobs may fail.***
In the above case, jobs can be manually retried after mitigation.

***2. New self-signed certificate needs to be provisioned on all hybrid workers connected to that automation account.*** ([steps](https://docs.microsoft.com/en-us/azure/automation/automation-hrw-run-runbooks#runas-script))

***3. In case the jobs are critical, please follow manual mitigation steps***

## Prerequisites

1. .NET framework 4.7.2 or later installed.
2. Windows PowerShell version 5.1(64-bit) or later installed and run with Administrator permissions.
3. Azure Az PowerShell module latest version installed, having minimum version Az.Accounts (2.5.4)`, `Az.Resources (4.4.0)` & `Az.Automation (1.7.1)` cmdlets
4. You need the following permissions on the Azure user account:

   a. ‘Contributor’ access on the Azure subscription that has the Azure Automation account, and
   
   b. Owner permissions on the associated Run-As-Account Azure AD Application.

## Examples

1. To assess and mitigate single AppID

```powershell
.\CVE-2021-42306-AutomationAssessAndMitigate.ps1 -AppId 344456-2244-45674-8340-20d95505566
```

2. To assess and mitigate set of subscriptions

```powershell
.\CVE-2021-42306-AutomationAssessAndMitigate.ps1 -SubscriptionIds subId1,subId2
```

3. To execute in Gov CLouds use `-Env`, supported values `AzureCloud, AzureUSGovernment, AzureChinaCloud`

```powershell
.\CVE-2021-42306-AutomationAssessAndMitigate.ps1 -SubscriptionIds subId1,subId2 -Env AzureUSGovernment
```

## Manual mitigation steps

1. Renew the certificate using the manual steps mentioned in the [manage runas account documentation](https://docs.microsoft.com/en-us/azure/automation/manage-runas-account).
2. Update the certificate on all HRWs that use the Run As Account for authentication ([steps](https://docs.microsoft.com/en-us/azure/automation/automation-hrw-run-runbooks#runas-script)).
3. Wait for jobs which started before the certificate renewal to complete.
4. Delete the older certificate from the AAD application.

## What does the script do?

### Assess

1. Login to Azure.
2. If AppId is given as input, then the script evaluates if the Azure-AD App is managed by Azure Automation or not, and accordingly fetch respective Automation account details.
3. if subscription(s) is given as input, then the script fetches all accessible automation accounts through Azure resource graph API for the given subscription(s).
4. After fetching Automation accounts, for each automation account, the script assess the RunAs Azure-AD App and finds whether it is impacted or not by using Azure Graph API.

### Mitigate

For each impacted Automation RunAs Azure-AD App, following steps are performed.

1. Create new self-signed certificate.
2. Delete older certificates in Azure-AD App.
3. Update Key credentials with new certificate created in step #1.
4. Update Automation account with new certificate created in step #1.
