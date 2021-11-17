<#
.SYNOPSIS
    Assess credential health of the Azure Automation RunAs account and rotate credential. 

.DESCRIPTION
    This script can be used to assess credential risk of an Azure AD application associated with an Automation RunAs Account and helps renew the App certificate.
    It processes all the accessible Automation Accounts with AzureRunAsConnection and renews the certificate.
    Provide the AppId OR the list of subscription ids as inputs.

    Prerequisites: This script needs
        Automation & AD Az cmdlets
        Powershell 5.1 (not Powershell 7) - for mitigation
        Administrator console - for mitigation

    Access required:
        Assess - Needs Reader access
        Remediate - Needs Application Owner access to respective AAD application and Automation Contributor access to the automation account

    Examples to run :
        1) To assess and mitigate single AppID - Ex:  .\AssessAndMitigate.ps1 -AppId 344456-2244-45674-8340-20d95505566
        2) To assess and mitigate set of subscriptions - Ex: .\AssessAndMitigate.ps1 - SubscriptionIds subId1,subId2

.PARAMETER SubscriptionIds
    [Optional] Filter for accounts from the given subscriptions. If none is provided, all subscriptions accessible by the user are evaluated.

.PARAMETER AppId
    [Optional] Assess the given Aad app ID and  mitigate if it belong to azure automation.

.PARAMETER Env
    [Optional] Cloud environment name. 'AzureCloud' by default.

.PARAMETER Verbose
    [Optional] Enable verbose logging

.EXAMPLE
    PS> .\AssessAndMitigate.ps1 -AppId <appId>

.EXAMPLE
    PS> .\AssessAndMitigate.ps1 -SubscriptionIds subId1,subId2

.NOTES
    1. All older certificates uploaded to the AAD app will be removed. This will cause currently running jobs on that automation account to fail. These jobs can be retried manually.
    2. If you are using a CA-signed or third party certificates, then you need to manually renew the certificate.

.AUTHOR Azure Automation team

.VERSION 0.9.0
#>

#Requires -Modules Az.Resources, Az.Automation
#Requires -PSEdition Desktop
#Requires -RunAsAdministrator

[CmdletBinding()]
Param(
    [string[]]
    $SubscriptionIds,

    [string]
    $AppId,

    # Max number of retries for List Applications or List ServicePrincipals MS Graph request
    [int]
    $MaxRetryLimitForGraphApiCalls = 5,

    [ValidateSet("AzureCloud", "AzureUSGovernment", "AzureChinaCloud")]
    [Parameter(Mandatory = $false, HelpMessage = "Cloud environment name. 'AzureCloud' by default")]
    [string]
    $Env = "AzureCloud"
)

function Show-Description {
    Write-Output ""
    Write-Warning "The script can be run to either to assess single App ID (belonging to Automation) OR a set of subscriptions."
    Write-Output ""

    Write-Output "This script gets all automation accounts which have an RunAs account and renews the certificate used."
    Write-Warning "Mitigating will delete *ALL* older certificates from the AAD application used by the RunAs account. This will cause currently running jobs to fail. They need to be retried manually."
    Write-Output "If the RunAs AAD app is used across multiple automation accounts, then each account's RunAs connection needs to be updated with the new certificate thumbprint."
    Write-Output "Manually install the self-signed certificate on all Hybrid workers."
    Write-Output ""
    Write-Output "Reader permissions are required for assessment and Application Owner & Automation Contributor permissions for mitigation"

    Write-Output ""
    Write-Warning "The mitigation should not be run if you are using CA-signed or third party certificates with the RunAs account. In that case, you need to renew the certificate manually if you are impacted."
    Write-Output ""
}

Function Get-MSGraphEndpoint
{
    param(
        [string]
        $Env
    )

    switch ($Env)
    {
        "AzureCloud" { return "https://graph.microsoft.com" }
        "AzureChinaCloud" { return "https://microsoftgraph.chinacloudapi.cn" }
        "AzureUSGovernment" { return "https://graph.microsoft.us" }
        default { throw "$($Env) is not a valid cloud environment." }
    }
}

class AutomationAccount {
    [string] $Name
    [string] $ResourceId
    [string] $Region
    [string] $ResourceGroup
    [string] $SubscriptionId
    [string] $RunAsAppId
    [DateTimeOffset] $RunAsConnectionCreationTime
    [bool] $UsesThirdParytCert
}

$ImpactedAccounts = New-Object System.Collections.ArrayList

function Assess-Impact {
    Write-Output ""
    Write-Output "==================="
    Write-Output "Assessing impact..."
    Write-Output "==================="

    # Get all automation accounts accessible to current user
    $queryPayload = @{
        query = 'resources | where type == "microsoft.automation/automationaccounts"'
        options = @{
        '$top' = 10000
        '$skip' = 0
        '$skipToken' = ""
        'resultFormat' = "table"
        }
    }
    $payload = $queryPayload | ConvertTo-Json

    $resp = Invoke-AzRestMethod -Path "/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01" -Method POST -Payload $payload
    $resp = $resp.Content | ConvertFrom-Json

    Write-Output "$($resp.totalRecords) automation accounts found in all accessible subscriptions. Checking if they are impacted..."
    $allAccounts = New-Object System.Collections.ArrayList
    $defaultDate = (Get-Date 01-01-1970)
    foreach ($row in $resp.data.rows)
    {
        $a = [AutomationAccount]@{
            ResourceId = $row[0]
            Name = $row[1]
            Region = $row[5]
            ResourceGroup = $row[6]
            SubscriptionId = $row[7]
            RunAsAppId = ""
            RunAsConnectionCreationTime = $defaultDate
            UsesThirdParytCert = $false
        }
        Write-Debug "$($a.Name), $($a.Region), $($a.ResourceGroup), $($a.SubscriptionId)"

        $allAccounts.Add($a) > $null
    }

    Assess-ImpactBySubscriptionGroup $allAccounts
}

function Assess-ImpactBySubscriptionGroup {
    param ($accounts)

    if ($null -ne $SubscriptionIds -and $SubscriptionIds.Count -ne 0)
    {
        Write-Verbose "Filtering by subscription: $SubscriptionId"
        $accounts = $accounts | Where-Object { $_.SubscriptionId -in $SubscriptionIds }
    }

    # Group by subscription ID
    $accountsGroup = $accounts | Group-Object { $_.SubscriptionId }

    foreach ($item in $accountsGroup) {
        Write-Output ""
        Write-Output "Accounts in subscription $($item.Name): $($item.Group.Count)"
        Select-AzSubscription -SubscriptionId $item.Name > $null

        Write-Output "Potentially impacted accounts:"
        foreach ($a in $item.Group) {
            Assess-Account $a
        }
    }
}

function Assess-ImpactByAppId {

    # Check aad app id is valid or not
    if ([string]::IsNullOrWhiteSpace($AppId))
    {
        Write-Verbose "Given AAD App ID is invalid, Provide valid AAD App ID: $AppId"
    }

    # Get the given aad app
    $aadApp = Get-AzADApplication -ApplicationId $AppId

    # Check if the AAD app belong to Azure automation
    if( $null -ne $aadApp -and $aadApp.HomePage.ToLower().Contains("providers/microsoft.automation/automationaccounts")) {

        $resoureDetails = ParseResourceId $aadApp.HomePage

        if( $null -ne $resoureDetails -and $resoureDetails.Count -eq 3 -and
            ![string]::IsNullOrWhiteSpace($resoureDetails[0]) -and ![string]::IsNullOrWhiteSpace($resoureDetails[1]) -and ![string]::IsNullOrWhiteSpace($resoureDetails[2])) {

                Write-Output "Given App ID belongs to Azure automation, proceeding for further accessment. Subscription: $($resoureDetails[0]), ResourceGroup: $($resoureDetails[1]), Automation account name: $($resoureDetails[2])"
                Select-AzSubscription -SubscriptionId $resoureDetails[0] > $null
                $account = Get-AzAutomationAccount -ResourceGroupName $resoureDetails[1] -Name $resoureDetails[2]
                $defaultDateTime = (Get-Date 01-01-1970)

                if( $null -ne $account){

                    Write-Output "Got the automation account belonging to the given AAD app id"
                    $a = [AutomationAccount]@{
                        ResourceId = $aadApp.HomePage
                        Name = $account.AutomationAccountName
                        Region = $account.Location
                        ResourceGroup = $account.ResourceGroupName
                        SubscriptionId = $account.SubscriptionId
                        RunAsAppId = ""
                        RunAsConnectionCreationTime = $defaultDateTime
                        UsesThirdParytCert = $false
                    }

                    Assess-Account $a
                } else {
                    Write-Output "Unable to get the automation account belong to the given AAD App Id. This is an orphaned App."
                }
            } else {
                Write-Output "Given Aad app id is not associated to Azure automation, hence skipping the further assessment."
            }
    } else {
        Write-Output "Given Aad app id is not associated to Azure automation, hence skipping the further assessment."
    }
}

function Assess-Account {
    param ([AutomationAccount] $account)

    Write-Verbose "Assessing account $($account.ResourceId)"
    # Get the RunAs connection
    $conn = Get-AzAutomationConnection -AutomationAccountName $a.Name -ResourceGroupName $a.ResourceGroup -Name "AzureRunAsConnection" -ErrorAction SilentlyContinue

    if ($null -ne $conn -and $conn.ConnectionTypeName -eq "AzureServicePrincipal") {
        $a.RunAsAppId = $conn.FieldDefinitionValues.ApplicationId
        $a.RunAsConnectionCreationTime = $conn.CreationTime

        Assess-CertificatesOnApp $account
    }
    else {
        Write-Verbose "Account $($a.ResourceId) is not impacted"
    }
}

function Assess-CertificatesOnApp {
    param ([AutomationAccount] $account)

    $url = "$($MsGraphEndpoint)/beta/applications?`$filter=appId eq '$($account.RunAsAppId)'&`$select=id,appId,keyCredentials"

    $resp = Make-MSGraphRequest -Url $url -MaxRetryLimit $MaxRetryLimitForGraphApiCalls

    if ($null -ne $resp -and $null -ne $resp.value.keyCredentials) {
        foreach ($keyCred in $resp.value.keyCredentials) {
            if (($keyCred.Key.Length -gt 0) -and ($keyCred.type -eq 'AsymmetricX509Cert') -and (($keyCred.usage -eq 'Verify') -or ($keyCred.usage -eq 'Encrypt'))) {
                # check cert is not expired
                if ((Get-Date $keyCred.endDateTime) -gt (Get-Date)) {
                    Assess-Certificate $account $keyCred
                }
            }
        }
    }
    else {
        Write-Output "Unable to Get the AAD App ID metadata. AAD App Id Query - $($url)"
    }
}

# Make MS Graph request with retry and exponential backoff
Function Make-MSGraphRequest
{
    param(
        [string]
        $Url,

        [int]
        $MaxRetryLimit,

        [int]
        $flatMinSeconds = 10,

        [bool]
        $AddConsistencyLevel
    )

    $headers = @{
        "Authorization" = "Bearer $($MsGraphToken)"
    }

    if ($AddConsistencyLevel) {
        $headers["ConsistencyLevel"] = "eventual"
    }

    for ($i=1; $i -le $MaxRetryLimit; $i+=1)
    {
        try
        {
            Write-Verbose "GET $($Url)"
            $result = Invoke-RestMethod -Uri $Url -Headers $headers -Method "GET" -Verbose:$false
            break
        }
        catch
        {
            if ($_.Exception.Response.StatusCode.value__ -eq 429)
            {
                # Sleep then retry (Exponential backoff)
                $sleepDuration = [Math]::Pow(2,$i) + $flatMinSeconds
                Write-Verbose "Retry after sleeping for $($sleepDuration) seconds"
                Start-Sleep -s $sleepDuration
                continue
            }

            if ($_.Exception.Response.StatusCode.value__ -eq 404)
            {
                Write-Warning "AAD Object not found. Query - '$($Url)'"
            }

            Write-Warning "Unexpected Error. Try again later with -SkipTokenUrl '$($Url)'"
        }
    }

    if ($i -gt $MaxRetryLimit)
    {
        $Url = Trim-Url -Url $Url
        Write-Warning "Max backoff retry limit reached. Try again later with -SkipTokenUrl '$($Url)'"
    }

    return $result
}


function Assess-Certificate {
    param (
        [AutomationAccount] $account,
        $keyCred
    )

    $automationCertIssuerName = "DC=$($account.Name)_$($account.ResourceGroup)_$($account.SubscriptionId)"

    if ($keyCred.hasExtendedValue -eq $true) {
        $ImpactedAccounts.Add($account) > $null
        Write-Output "Account $($account.ResourceId) is impacted for cert: $($keyCred.customKeyIdentifier)"
    }
    else {
    }

    try {
        $certBytes = [Convert]::FromBase64String($keyCred.key)
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
    }
    catch {
        Write-Warning "Unable to get cert for $($account.ResourceId)"
    }

    if ($null -ne $cert) {
        if ($cert.Issuer -eq $automationCertIssuerName) {
            Write-Verbose "Account $($account.ResourceId) uses a self-signed cert with thumbprint: $($cert.Thumbprint)."
        }
        else {
            $account.UsesThirdParytCert = $true
            Write-Output "Account $($account.ResourceId) uses a third-party certificate with issuer: $($cert.Issuer)."
        }
        Write-Debug "issuer: $($cert.Issuer), subject: $($cert.Subject), expiry: $($cert.NotAfter), extValue: $($keyCred.hasExtendedValue)"
    }
}

function Mitigate-Incident {
    param (
        $accounts
    )

    if ($accounts.Count -eq 0) {
        Write-Output ""
        Write-Output "No impacted accounts to mitigate."
        return
    }

    Write-Output ""
    Write-Output "======================"
    Write-Output "Starting mitigation..."
    Write-Output "======================"
    foreach ($a in $accounts)
    {
        if ($a.UsesThirdParytCert) {
            Write-Output "$($a.ResourceId) uses a third-party certificate."
            $thirdPartyRenew = Read-Host "Do you want to renew this account with a self-signed certificate for mitigation? (Y/N): "

            if ($thirdPartyRenew -ne "Y" -and $thirdPartyRenew -ne 'y') {
                continue
            }
        }

        Write-Output ""
        $renew = Read-Host "Renew RunAs certificate for account $($a.ResourceId) (Y/N): "

        if ($renew -eq "Y" -or $renew -eq 'y') {
            Remediate-Account $a
        }
    }
}

function Remediate-Account {
    param ([AutomationAccount]$account)

    Write-Output ""
    Write-Output "Rotating certificate for $($account.ResourceId)"
    Select-AzSubscription -SubscriptionId $account.SubscriptionId > $null

    $appId = $account.RunAsAppId
    $subId = $account.SubscriptionId
    $resourceGroup = $account.ResourceGroup
    $accountName = $account.Name

    # To remediate AAD App, user should have Automation Contributor role access and Application Administrator permission on AAD App
    # Checking user write access on automation account.
    $writePermission = Check-WriteAccessOnAutomationAccount $account
    if(!$writePermission ) {
        Write-Error "User does not have write permission on account $($account.ResourceId), hence skipping the remediation"
        return
    }

    Write-Verbose "User has write permission on Automation account $($account.ResourceId)"

    Write-Debug "Creating new certificate"
    $certName = "$($accountName)_$($resourceGroup)_$($subId)"
    $cert = New-SelfSignedCertificate -KeyUsageProperty All -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -FriendlyName $certName -Subject "DC=$certName" -HashAlgorithm SHA256 -KeyLength 2048 -KeyExportPolicy ExportableEncrypted
    $certString = [convert]::tobase64string($cert.RawData)

    Add-Type -AssemblyName System.Web
    $securePassword = ConvertTo-SecureString $([System.Web.Security.Membership]::GeneratePassword(25, 10)) -AsPlainText -Force
    Export-PfxCertificate -FilePath "$pwd\$certName.pfx" -Cert $cert -Password $securePassword -NoProperties > $null

    Write-Verbose "Deleting existing certs on app with AppId: $appId"
    $creds = Get-AzADAppCredential -ApplicationId $appId | Where-Object { $_.Type -eq "AsymmetricX509Cert" }
    foreach ($cred in $creds) {
        Remove-AzADAppCredential -ApplicationId $appId -KeyId ([Guid]::Parse($cred.KeyId))
        if (!$?) {
            Write-Error "Failed to remove existing certificates from the AAD application."
            return
        }
    }

    Write-Verbose "Adding the new certificate on the AAD application"
    New-AzADAppCredential -ApplicationId $appId -CertValue $certString -StartDate $cert.NotBefore -EndDate $cert.NotAfter > $null
    if (!$?) {
        Write-Error "Failed to add new certificate to the AAD application."
        return
    }

    Write-Verbose "Creating the RunAs certificate asset"
    Remove-AzAutomationCertificate -AutomationAccountName $accountName -ResourceGroupName $resourceGroup -Name "AzureRunAsCertificate" -ErrorAction SilentlyContinue > $null
    New-AzAutomationCertificate -AutomationAccountName $accountName -ResourceGroupName $resourceGroup -Name "AzureRunAsCertificate" -Exportable -Path "$pwd\$certName.pfx" -Password $securePassword > $null
    if (!$?) {
        Write-Error "Failed to create new RunAs certificate"
        return
    }

    Write-Verbose "Update the RunAs connection"
    Set-AzAutomationConnectionFieldValue -AutomationAccountName $accountName -ResourceGroupName $resourceGroup -Name "AzureRunAsConnection" -ConnectionFieldName CertificateThumbprint -Value $cert.Thumbprint > $null

    Write-Output "Certificate rotation complete for the account $($accountName)."
    Write-Output "Install $pwd\$certName.pfx on hybrid workers of $($account.ResourceId)."
    Write-Output ""
}

function Check-WriteAccessOnAutomationAccount {
    param ([AutomationAccount]$account)

    $resourceGroup = $account.ResourceGroup
    $accountName = $account.Name

    #To remidiate AAD App,user should have Automation Contributor role access and admin permission on AAD App
    # Checking user write access on automation account.
    $VariableName = "Remediation_"+[System.IO.Path]::GetRandomFileName()
    $var = Get-AzAutomationVariable -ResourceGroupName $resourceGroup -AutomationAccountName $accountName -Name $VariableName -ErrorAction SilentlyContinue > $null
    while( $null -ne $var)
    {
        $VariableName = "Remediation_"+[System.IO.Path]::GetRandomFileName()
        $var = Get-AzAutomationVariable -ResourceGroupName $resourceGroup -AutomationAccountName $accountName -Name $VariableName -ErrorAction SilentlyContinue > $null
    }

    if( $null -eq $var) {
        $var = New-AzAutomationVariable -ResourceGroupName $resourceGroup -AutomationAccountName $accountName -Name $VariableName -Value $VariableName -Encrypted $false
        if( $null -ne $var) {
            Remove-AzAutomationVariable -ResourceGroupName $resourceGroup -AutomationAccountName $accountName -Name $VariableName
            return $true;
        }
    }

    return $false
}

function ParseResourceId {
    param (
       [string]$resourceID
   )
   $array = $resourceID.Split('/')
   $indexSubscriptionId = 0..($array.Length -1) | where {$array[$_] -ieq 'subscriptions'}
   $indexResourceGroup = 0..($array.Length -1) | where {$array[$_] -ieq 'resourcegroups'}
   $result = $array.get($indexSubscriptionId+1), $array.get($indexResourceGroup+1), $array.get($array.Length -1)
   return $result
}


# Start point for the script
Show-Description

Connect-AzAccount -Environment $Env -ErrorAction Stop > $null
$MsGraphEndpoint = Get-MSGraphEndpoint $Env
$MsGraphToken = (Get-AzAccessToken -ResourceUrl $MsGraphEndpoint).Token

if(![string]::IsNullOrWhiteSpace($AppId)){
    Write-Output "Start Assessment for given AAD App ID."
    # Assess given Aad App ID and mitigate if it belong to Azure automation.
    Assess-ImpactByAppId

    Mitigate-Incident $ImpactedAccounts
} elseif ($null -ne $SubscriptionIds -and $SubscriptionIds.Count -ne 0) {
    Write-Output "Start Assessment for given Subscriptions."
    # Assess all the given subscriptions and mitigate all the App Id's belong to Azure automation
    Assess-Impact

    Mitigate-Incident $ImpactedAccounts
}


