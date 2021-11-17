# Azure Automation RunAs Account AAD CVE-2021-42306 – remediation guidance 

## Disclaimer

Guidance in this document applies only in relation to the mitigation steps necessary for the issue disclosed in the [CVE](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42306) and detailed in [Microsoft Security Response Center blog](https://aka.ms/CVE-2021-42306-AAD). Do not use this guidance as general credential rotation procedure.

This issue can be mitigated manually or by using the automated remediation script. This document is organized in the following sections :

1. [Manual Mitigation Steps](#Manual-Mitigation-Steps)
2. [Automated Remediation Script](#Automated-Remediation-Script)
3. [Frequently Asked Questions](#Frequently-asked-questions)


## Manual Mitigation Steps   

  1. Verify an appropriate user that has the required permissions to carry out the remediation steps. 
  2. Identify a suitable time when no Automation Runbooks will be running and none are scheduled to be running at which to run the remediation.  
  3. Identify any impacted Automation Accounts, and those which use 3rd party/customer certificates. 
  4. If there is no suitable time when no runbooks are running to do the remediation, then note the running jobs at this point immediately prior to the renewal. 
  5. Renew the Automation Run As Accounts of any impacted Automation Accounts. 
  6. Import the new certificates to the Hybrid Runbook Workers (HRWs) which use Run As Account authentication. 
  7. Confirm that any jobs running when the renewal took place are now complete and delete the old certificate from the Azure Active Directory(AD) Application. 

### Step by step guide

1. Identify the impacted Automation Accounts.
    1. The easiest way to identify the impacted Automation Accounts is using the provided Automation script. It will identify the impacted Automation accounts and then prompts you whether to remediate each discovered account in turn.
    2. Alternately you can check each Automation Account manually in each of your subscriptions to verify if the Azure Run As Account exists and that it hasn't expired.

2. Verifying permissions - Before beginning the remediation steps, ensure the user has the following permissions.
    1. Write permissions on the Automation Account to be remediated, which is granted to the Owner and Contributor roles. 

          ![image](https://user-images.githubusercontent.com/29953537/142232076-d25cf33b-ce59-4f57-be64-29696a185747.png)

    2. Owner of the associated Azure AD Application… 

          ![image](https://user-images.githubusercontent.com/29953537/142234634-aba3e378-7f01-46ea-9251-fd35f1309221.png)

          ![image](https://user-images.githubusercontent.com/29953537/142234859-a45a40a6-e1a8-45b8-b6aa-414dcca1f561.png)

    3. Or that the user belongs to one of these roles within Azure AD 
        1. Application Administrator 
        2. Cloud Application Administrator 
        3. Global Administrator 

3. Identify a time period when no runbook will be executing for your Automation Account. If you were unable to find a time when no runbooks are running, then list all the running queued jobs by following two methods, before you begin to renew the certificate.

    1. Portal 
         
          ![image](https://user-images.githubusercontent.com/29953537/142236331-c0052606-ac9e-43e7-a8c1-8613b79be9a6.png)

    2. PowerShell 

        >`$ResourceGroupName = "<INSERT AUTOMATION ACCOUNT RESOURCE GROUP NAME HERE>"`   
          `$AutomationAccountName = "<INSERT AUTOMATION ACCOUNT NAME HERE>"`    
          `$jobsInflight = Get-AzAutomationJob -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomatonAccountName | where-object {$PSItem.Status -notin ("Completed","Failed","Stopped", "Suspended")}`   
          `$jobsinflight `   


4. Manually renew the Run As account in each Automation account. 
    1. Step #1
          ![image](https://user-images.githubusercontent.com/29953537/142238772-2574f2aa-c7af-4970-b6be-394475a84eea.png)
    2. Step #2
          ![image](https://user-images.githubusercontent.com/29953537/142238906-9df4c728-fb17-4f66-894e-925908b8a9a8.png)   

5. Import the certificates to your Hybrid Runbook Workers (HRWs) that use Run As Account authentication following the steps [mentioned in public docs](https://docs.microsoft.com/en-us/azure/automation/automation-hrw-run-runbooks#runas-script) 

6. Now verify that the jobs that were running in step 4 have completed (if you couldn't remediate when no jobs were running) and  finally delete the older certificates from the Automation Azure AD Applications. 

7. Once that certificate has been deleted, issue is successfully mitigated for that account. 

## Automated Remediation Script

Alternately, once you have checked the user permissions you can run the assess and remediate script, which automate the detection and remediation of Automation Accounts in your chosen subscriptions. Script details below. 

### Details
This script will assess automation account which has configured RunAs accounts and checks if the corresponding AAD application is impacted or not. If it is impacted, on confirmation it will renew the key credentials of Azure-AD App by deleting the older certificate(s) and uploading new self-signed certificate to the Azure-AD App, which will mitigate the issue.

### Usage
The script can be used to run at a time on single AAD App( belong to automation) or set of subscriptions. Please note that the script will work for Automation managed RunAs AAD Apps, and if you are using Third-party/CA-signed certificates, please follow manual mitigation steps mentioned below

>*It is highly recommended to try with single subscription which is having not more than one Automation account or with single AppID option.*
>
>*If the runbooks uses RunAs Azure-AD App to access the resources through Az/AzureRM cmdlets, access-tokens will become invalid due to certificate changes, and so jobs may fail.In case the jobs are critical, please follow manual mitigation steps mentioned above*
>
>*New self-signed certificate needs to be provisioned on all hybrid workers connected to that automation account. ([detailed in public docs ](https://docs.microsoft.com/en-us/azure/automation/automation-hrw-run-runbooks#runas-script))*

### Prerequisites

1. .NET framework 4.7.2 or later installed.
2. Windows PowerShell version 5.1(64-bit) or later installed and run with Administrator permissions.
3. Azure Az PowerShell module latest version installed, having minimum version `Az.Accounts (2.5.4)`, `Az.Resources (4.4.0)` & `Az.Automation (1.7.1)` cmdlets
4. You need the following permissions on the Azure user account:
    1. ‘Contributor’ access on the Azure subscription that has the Azure Automation account, and
    2. Owner permissions on the associated Run-As-Account Azure AD Application.

### Examples

1. To assess and mitigate single AppID

    >`powershell
.\CVE-2021-42306-AutomationAssessAndMitigate.ps1 -AppId 344456-2244-45674-8340-20d95505566
`
2. To assess and mitigate set of subscriptions

    >`powershell
.\CVE-2021-42306-AutomationAssessAndMitigate.ps1 -SubscriptionIds subId1,subId2
`
3. To execute in Gov CLouds use `-Env`, supported values `AzureCloud, AzureUSGovernment, AzureChinaCloud`
    >`powershell
.\CVE-2021-42306-AutomationAssessAndMitigate.ps1 -SubscriptionIds subId1,subId2 -Env AzureUSGovernment
`

### What does the script do?

#### Detection

1. Login to Azure.
2. If AppId is given as input, then the script evaluates if the Azure-AD App is managed by Azure Automation or not, and accordingly fetch respective Automation account details.
3. if subscription(s) is given as input, then the script fetches all accessible automation accounts through Azure resource graph API for the given subscription(s).
4. After fetching Automation accounts, for each automation account, the script assess the RunAs Azure-AD App and finds whether it is impacted or not by using Azure Graph API.

#### Mitigation
For each impacted Automation RunAs Azure-AD App, following steps are performed.
1. Create new self-signed certificate.
2. Delete older certificates in Azure-AD App.
3. Update Key credentials with new certificate created in step #1.
4. Update Automation account with new certificate created in step #1.

## Frequently asked questions
Q: Does this affect the Classic Run As Accounts too?   
A: No, this only affects the Run As Account.

Q: Does this impact Automation Managed Identities?     
A: No, if you are using Managed Identities for Authentication, these are not impacted by this issue, but if you have recently switched over to using Managed Identities and you haven’t yet deleted the old Run As Accounts, you should do that now if they have not expired.
