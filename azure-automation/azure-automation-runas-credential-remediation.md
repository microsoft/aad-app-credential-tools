# Azure Automation application credential assessment and remediation guidance

If you are using Azure Automation’s Self signed certificate for automation run-as accounts created and not renewed between 10/15/2020 and 10/15/2021, please run the script [here](https://aka.ms/azure-automation-runas-cred-roll) using the App Id parameter from the csv attached to the email you received. Please do not run the script without the App Id parameter.

If using your own certificate in Azure Automation, take steps to [renew your certificate](https://docs.microsoft.com/en-us/azure/automation/manage-runas-account?WT.mc_id=Portal-Microsoft_Azure_Automation#renew-an-enterprise-or-third-party-certificate)  and remove the previous certificate used in the Azure AD Application as a precautionary measure regardless of the last renewed date.

## Prerequisites

1. Windows PowerShell version 5.1 or later installed.
2. Windows PowerShell running 64-bit version.
3. .NET framework 4.7.2 or later installed.
4. Azure Az PowerShell module latest version installed.
5. You need the following permissions on the Azure user account:
   - `Contributor` access on the Azure subscription that has the Azure Automation account, and
   - Owner permissions on the associated Run-As-Account Azure AD Application.

## Example

`.\AutomationAssessAndMitigate.ps1 -AppId <AppID-GUID>`
