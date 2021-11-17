<#
.SYNOPSIS
Check if the script is invoked by administrator.
#>
function Test-Administrator  
{  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

    if (!$isAdmin){
        Write-Host "This script needs to be run in Administrator mode. Aborting..." -ForegroundColor Red
        Exit -1;
    }
}

Test-Administrator
$PSDefaultParameterValues = @{}
$PSDefaultParameterValues += @{'Remove-AzKeyVaultCertificate:ErrorAction' = 'Stop'}
$PSDefaultParameterValues += @{'New-AzKeyVaultCertificatePolicy:ErrorAction' = 'Stop'}
$PSDefaultParameterValues += @{'Add-AzKeyVaultCertificate:ErrorAction' = 'Stop'}
$PSDefaultParameterValues += @{'Get-AzKeyVaultCertificateOperation:ErrorAction' = 'Stop'}
$PSDefaultParameterValues += @{'Get-AzADApplication:ErrorAction' = 'Stop'}
$PSDefaultParameterValues += @{'Remove-AzADAppCredential:ErrorAction' = 'Stop'}
$PSDefaultParameterValues += @{'New-AzADAppCredential:ErrorAction' = 'Stop'}
$PSDefaultParameterValues += @{'Select-AzSubscription:ErrorAction' = 'Stop'}
$PSDefaultParameterValues += @{'Connect-AzAccount:ErrorAction' = 'Stop'}
$PSDefaultParameterValues += @{'Import-PFXCertificate:ErrorAction' = 'Stop'} 
$PSDefaultParameterValues += @{'Get-AzKeyVaultSecret:ErrorAction' = 'Stop'}
$PSDefaultParameterValues += @{'Set-AzKeyVaultSecret:ErrorAction' = 'Stop'}
$PSDefaultParameterValues += @{'Get-AzKeyVaultCertificate:ErrorAction' = 'Stop'}
$PSDefaultParameterValues += @{'Set-AzKeyVaultCertificatePolicy:ErrorAction' = 'Stop'}
$PSDefaultParameterValues += @{'Get-AzKeyVaultCertificatePolicy:ErrorAction' = 'Stop'}

$CurrentDateTime       =  Get-Date -Format "MM-dd-yyyyTHH-mm-ss"
$UpdateCertsDir        =  "$env:ProgramData\Microsoft Azure\UpdateCert"
$ConfigFileDir         =  "$env:ProgramData\Microsoft Azure\Config"
$ConfigFilesBackupDir  =  "$env:ProgramData\Microsoft Azure\ConfigFilesBackup"
$LogFile               =  $UpdateCertsDir + "\UpdateCert-" + $CurrentDateTime + ".log"

# Configuration files.
$ApplianceJsonFilePath            =  "$ConfigFileDir\appliance.json"
$DiscoveryJsonFilePath            =  "$ConfigFileDir\discovery.json"
$MarsAgentJsonFilePath            =  "$ConfigFileDir\MarsAgent.json"
$PushInstallAgentJsonFilePath     =  "$ConfigFileDir\pushinstallagent.json"
$RCMProxyAgentJsonFilePath        =  "$ConfigFileDir\rcmproxyagent.json"
$RcmReplicationAgentJsonFilePath  =  "$ConfigFileDir\rcmreplicationagent.json"
$RcmReprotectAgentJsonFilePath    =  "$ConfigFileDir\rcmreprotectagent.json"
$ProcessServerJsonFilePath        =  "$ConfigFileDir\processserver.json"
$ServerDiscoveryJsonFilePath      =  "$ConfigFileDir\serverdiscovery.json"
$ProcessServerConfigFile          =  "$env:SystemDrive\Program Files\Microsoft Azure Site Recovery Process Server\home\svsystems\etc\ProcessServer.conf"
$Version = "1.0.0.0"

# Registries.
$DRARegistry  = "HKLM:\Software\Microsoft\Azure Site Recovery\Registration"
$MARSRegistry = "HKLM:\Software\Microsoft\Windows Azure Backup\Config\InMageMT"

$ServicesList = New-Object Collections.Generic.List[String]
$ServicesList.Add("cxprocessserver")
$ServicesList.Add("pushinstallagent")
$ServicesList.Add("rcmproxyagent")
$ServicesList.Add("obengine")
$ServicesList.Add("MarsAgent")
$ServicesList.Add("amserverdiscoverysvc")
$ServicesList.Add("dra")
$ServicesList.Add("rcmreprotectagent")
$ServicesList.Add("amvmwdiscoverysvc")
$ServicesList.Add("rcmreplicationagent")
$ServicesList.Add("ProcessServer")
$ServicesList.Add("ProcessServerMonitor")

# Global variables.
$global:AgentCertThumbprint          =  $null
$global:FailbackCertThumbprint       =  $null
$global:MARSCertThumbprint           =  $null
$global:DiscoveryCertThumbprint      =  $null
$global:ResourceGroupName            =  $null
$global:SubscriptionID               =  $null
$global:FabricName                   =  $null
$global:VaultName                    =  $null
$global:ApplianceName                =  $null
$global:KVName                       =  $null
$global:TenantId                     =  $null
$global:FailbackAgentAuthCertName    =  $null
$global:MarsAgentAuthCertName        =  $null
$global:DiscoveryAuthCertName        =  $null
$global:AgentAuthCertName            =  $null
$global:FailbackAadAppId             =  $null
$global:MarsAgentAadAppId            =  $null
$global:DiscoveryAadAppId            =  $null
$global:AgentAadAppId                =  $null
$global:AgentSpnCertSubject          =  "CN=AgentSpnCert"
$global:FailbackAgentSpnCertSubject  =  "CN=FailbackAgentSpnCert"
$global:DiscoverySpnCertSubject      =  "CN=DiscoverySpnCert"
$global:MarsSpnCertSubject           =  "CN=MarsSpnCert"
$global:CertRollOverStatusKeyName    =  "AadIssueCertRollOverStatus"
$global:CertRollOverStatusValue      =  "Complete"
$global:IsCertRollOverComplete       =  $false
$global:AgentAuthCertSuffix          = "agentauthcert"
$global:DiscoveryAuthCertSuffix      = "discoveryauthcert"
$global:FailbackAgentAuthCertSuffix  = "failbackagentauthcert"
$global:MarsAgentAuthCertSuffix      = "marsagentauthcert"

<#
.SYNOPSIS
Add content to log.
#>
function Log($string){
    $date = (Get-Date -Format "dd-MM-yyyy_HH-mm-ss").ToString()
    Add-Content $LogFile "$date :: $string" -ErrorAction SilentlyContinue
}

<#
.SYNOPSIS
Log information.
#>
function Log-Info($string){
    Log $string
	Write-Host $string -ForegroundColor White
}

<#
.SYNOPSIS
Log success information.
#>
function Log-Success($message){
	Log $message
	Write-Host $message -ForegroundColor Green
}

<#
.SYNOPSIS
Log error.
#>
function Log-Error([string] $OutputText)
{
    Write-Host $exception -ForegroundColor Red
    Log($exception)
}

<#
.SYNOPSIS
Log error and exit.
#>
function LogErrorAndExit([string]$exception){
    Write-Host $exception -ForegroundColor Red
    Log($exception)
    Exit -1
}

<#
.SYNOPSIS
Get details from Appliance configuration file.
#>
function GetDetailsFromApplianceConfig
{
    if (Test-Path $ApplianceJsonFilePath)
    {
        $applianceJsonContent = Get-Content $ApplianceJsonFilePath | Out-String | ConvertFrom-Json

        $RegistrationDetails = $applianceJsonContent.RegistrationSettings
        $AgentAuthenticationSpnDetails = $applianceJsonContent.AgentAuthenticationSpn
        $DiscoveryAuthenticationSpnDetails = $applianceJsonContent.DiscoveryAuthenticationSpn
        $FailbackAgentAuthenticationSpnDetails = $applianceJsonContent.FailbackAgentAuthenticationSpn
        $MarsAgentAuthenticationSpnDetails = $applianceJsonContent.MarsAgentAuthenticationSpn

        $global:ResourceGroupName = $RegistrationDetails.ResourceGroup
        $global:SubscriptionID = $RegistrationDetails.SubscriptionId
        $global:ApplianceName = $RegistrationDetails.Name
        $global:FabricName = $applianceJsonContent.FabricName
        $global:VaultName = $RegistrationDetails.RecoveryServicesVaultName
        $global:TenantId = $RegistrationDetails.TenantId
        $global:KVName = $applianceJsonContent.AzureKeyVaultArmId.Split('/')[-1]
        $global:FailbackAadAppId = $FailbackAgentAuthenticationSpnDetails.ApplicationId
        $global:MarsAgentAadAppId = $MarsAgentAuthenticationSpnDetails.ApplicationId
        $global:DiscoveryAadAppId = $DiscoveryAuthenticationSpnDetails.ApplicationId
        $global:AgentAadAppId = $AgentAuthenticationSpnDetails.ApplicationId
    }
    else
    {
         LogErrorAndExit "Unable to find $ApplianceJsonFilePath. This host has not been used as DR Appliance. Aborting..."
    }
}

<#
.SYNOPSIS
Update thumprint in configuration file.
#>
function UpdateThumbprintInConfigFile 
{
	param(
        [string] $ConfigPath,
        [string] $SectionName,
        [string] $CertThumbprint
    )

    Log-Info "Updating config file $ConfigPath"

    $JsonContent = Get-Content $ConfigPath| Out-String | ConvertFrom-Json 
    
    if ($JsonContent)
    {   
        $JsonContent.$SectionName.CertificateThumbprint = "$CertThumbprint"
        $JsonContent | ConvertTo-Json -Depth 10 | Out-String | Set-Content $ConfigPath
    }
    else
    {
         LogErrorAndExit "Unable to fetch information from $ConfigPath. Aborting..."
    }
}

<#
.SYNOPSIS
Restart the service.
#>
function RestartService 
{
	param(
        [string] $ServiceName
    )

    Log-Info "Restarting the service $ServiceName..."

    try
    {
        for($i = 0; $i -le 3; $i++)
        {
	        try
	        {
		        # Start the service.
		        Restart-Service -Name $ServiceName
		        break
	        }
	        catch
	        {
		        Log-Error "Exception ocurred while restarting the service $ServiceName. Retrying after 60 seconds..."
		        Start-Sleep -s 60
	        }

	        if ($i -eq 3)
	        {
		        throw "Exception occured while starting the $ServiceName service."
	        }
        }

        $serviceStatus = $null

        for($i = 0; $i -le 10; $i++)
        {	
	        try
	        {
		        # Check the service status.
		        $getService = Get-Service -Name $ServiceName
		        $serviceStatus = $getService.Status
		        Log-Info "Service $ServiceName status - $serviceStatus"

		        if ($serviceStatus -eq "Running")
		        {
			        break
		        }
		        else
		        {
			        Log-Info "Rechecking $ServiceName service status after 30 seconds..."
			        Start-Sleep -s 30
		        }
	        }
	        catch
	        {
		        Log-Error "Exception occurred while checking the $ServiceName service status. Retrying after 30 seconds..."
		        Start-Sleep -s 30
	        }
        }
	
        if ($serviceStatus -ne "Running")
	    {
		    throw "Unable to start the $ServiceName service."
	    }
    }
    catch
    {
        LogErrorAndExit "Unable to restart the service $ServiceName. Aborting..."
    }
}

<#
.SYNOPSIS
Stop the service.
#>
function StopService 
{
	param(
        [string] $ServiceName
    )

    Log-Info "Stopping the service $ServiceName..."

    try
    {
        for($i = 0; $i -le 3; $i++)
	    {
            try
            {
                # Stop the service.
                Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
                break
            }
            catch
            {
                Log-Error "Exception ocurred while stopping the service $ServiceName. Retrying after 60 seconds..."
                Start-Sleep -s 60
            }

            if ($i -eq 3)
	        {
		        throw "Exception occured while stopping the $ServiceName service."
	        }
        }

        $serviceStatus = $null

        for($i = 0; $i -le 10; $i++)
	    {
		    try
		    {
                # Check the service status.
                $getService = Get-Service -Name $ServiceName
                $serviceStatus = $getService.Status
                Log-Info "Service $ServiceName status - $serviceStatus"

                if ($serviceStatus -eq "Stopped")
                {
                    break
                }
                else
                {
                    Log-Info "Rechecking $ServiceName service status after 30 seconds..."
                    Start-Sleep -s 30
                }
		    }
		    catch
		    {
			    Log-Error "Exception while checking the $ServiceName service status. Retrying after 30 seconds..."
			    Start-Sleep -s 30
		    }
	    }

        if ($serviceStatus -ne "Stopped")
	    {
		    throw "Unable to stop the $ServiceName service."
	    }
    }
    catch
    {
        LogErrorAndExit "Unable to stop the service $ServiceName. Aborting..."
    }
}

<#
.SYNOPSIS
Update the registry.
#>
function UpdateRegistry
{
	param(
        [string] $RegistryPath,
        [string] $KeyName,
        [string] $KeyValue
    )

    try
    {
        Log-Info "Updating the registry $RegistryPath..."

        for($i = 0; $i -le 4; $i++)
	    {
		    try
		    {
                Set-ItemProperty -Path "$RegistryPath" -Name "$KeyName" -Value "$KeyValue"
                $RegistryKeyOutput = Get-ItemProperty -Path "$RegistryPath" -Name "$KeyName"
                break
		    }
		    catch
		    {
			    Log-Error "Exception: $_.Exception.Message"
			    Start-Sleep -s 10

                if ($i -eq 4)
	            {
		            throw "Exception occured while updating the $RegistryPath registry."
	            }
		    }
	    } 
    }
    catch
    {
        LogErrorAndExit "Unable to update the registry $RegistryPath. Aborting..."
    }
}

<#
.SYNOPSIS
Get certificate names from KeyVault.
#>
function GetCertNamesFromKeyVault
{
    $kvCerts = Get-AzKeyVaultCertificate -VaultName $global:KVName

    if ($kvCerts)
    {
        foreach ($kvcert in $kvCerts)
        {
            $kvCertName = $kvcert.Name

            if ($kvCertName.Contains("$global:FailbackAgentAuthCertSuffix"))
            {
                $global:FailbackAgentAuthCertName = $kvCertName
            }
            elseif ($kvCertName.Contains("$global:MarsAgentAuthCertSuffix"))
            {
                $global:MarsAgentAuthCertName = $kvCertName
            }
            elseif ($kvCertName.Contains("$global:DiscoveryAuthCertSuffix"))
            {
				if ($kvCertName.Contains("$global:ApplianceName"))
				{
					$global:DiscoveryAuthCertName = $kvCertName
				}
            }
            elseif ($kvCertName.Contains("$global:AgentAuthCertSuffix"))
            {
                $global:AgentAuthCertName = $kvCertName
            }
        }

        if ([string]::IsNullOrEmpty("$global:FailbackAgentAuthCertSuffix") -or 
            [string]::IsNullOrEmpty("$global:MarsAgentAuthCertSuffix") -or 
            [string]::IsNullOrEmpty("$global:DiscoveryAuthCertSuffix") -or
            [string]::IsNullOrEmpty("$global:AgentAuthCertSuffix"))
        {
            LogErrorAndExit "All the required certificates are not available in the Keyvault - $global:KVName. Aborting.."
        }

    }
    else
    {
        LogErrorAndExit "Unable to fetch certificates from the Keyvault - $global:KVName. Aborting..."
    }
}

<#
.SYNOPSIS
Create new certificate in KeyVault.
#>
function CreateNewCertificateInKeyVault($certName, $certSubject)
{
    try
    {
        $Policy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName $certSubject -IssuerName "Self" -ValidityInMonths 36 -KeySize 2048 
        $newCert = Add-AzKeyVaultCertificate -VaultName $global:KVName -Name $certName -CertificatePolicy $Policy

        $operationStatus = Get-AzKeyVaultCertificateOperation -VaultName $global:KVName -Name $certName

        $numRetries = 3;

        while ($numRetries -gt 0){
            if ($operationStatus.Status -ne "completed"){
                Start-Sleep -Seconds 5
            }
			else{
				break;
			}
            $operationStatus = Get-AzKeyVaultCertificateOperation -VaultName $global:KVName -Name $certName
            $numRetries--
        }
    }
    catch
    {
        LogErrorAndExit "Unable to create new certificate in KeyVault $global:KVName. Exception - $_.Exception.Message"
    }
}

<#
.SYNOPSIS
# Update certificate in  AAD application.
#>
function UpdateAadApplicationCertificate($aadAppId, $pfxcertificate, $certString, $newCert)
{
    try
    {
        # Export the same certificate in cer format to upload to AAD app
        $CertificateBytes = $pfxcertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert, "")
        $certString = [System.Convert]::ToBase64String($CertificateBytes)

        # Get AAD app object and delete all previous certificates.
        Get-AzADApplication -ApplicationId $aadAppId | Remove-AzADAppCredential -Force
        Start-Sleep -Seconds 10

        # Upload new certificate which is in CER format.
        New-AzADAppCredential -ApplicationId $aadAppId -CertValue $certString -StartDate $newCert.NotBefore -EndDate $newCert.Expires
        Start-Sleep -Seconds 10
    }
    catch
    {
        LogErrorAndExit "Unable to update certificate in AAD application $aadAppId. Exception - $_.Exception.Message"
    }
}

<#
.SYNOPSIS
Perform Certificate Import and Export actions.
#>
function PerformCertImportExportActions($aadAppId, $certName, $certThumbprintName, $certSubject)
{
    try
    {
        if ([string]::IsNullOrEmpty($aadAppId)){
            LogErrorAndExit "Aad app ID is null and it must be present to proceed. Aborting.."
        }
        
        if ([string]::IsNullOrEmpty($certName)){
            LogErrorAndExit "Certificate name is null and it must be present to proceed. Aborting.."
        }

        if ([string]::IsNullOrEmpty($certThumbprintName)){
            LogErrorAndExit "Certificate thumbprint name is null and it must be present to proceed. Aborting.."
        }

        if ([string]::IsNullOrEmpty($certSubject)){
            LogErrorAndExit "Certificate subject is null and it must be present to proceed. Aborting.."
        }

        if (!$global:IsCertRollOverComplete -or 
		    $certName -eq "$global:DiscoveryAuthCertName")
        {
            CreateNewCertificateInKeyVault $certName $certSubject
        }

        # Fetch the new certificate and its secret from keyvault.
        $newCert = Get-AzKeyVaultCertificate -VaultName $KVName -Name $certName

        if ($certThumbprintName -eq "$global:AgentAuthCertSuffix")
        {
            $global:AgentCertThumbprint = $newCert.Thumbprint
        }
        elseif ($certThumbprintName -eq "$global:DiscoveryAuthCertSuffix")
        {
		    $global:DiscoveryCertThumbprint = $newCert.Thumbprint
        }
        elseif ($certThumbprintName -eq "$global:FailbackAgentAuthCertSuffix")
        {
            $global:FailbackCertThumbprint = $newCert.Thumbprint
        }
        elseif ($certThumbprintName -eq "$global:MarsAgentAuthCertSuffix")
        {
            $global:MARSCertThumbprint = $newCert.Thumbprint
        }

		$secret = Get-AzKeyVaultSecret -VaultName $global:KVName -Name $newCert.Name -AsPlainText
		$pfxUnprotectedBytes = [Convert]::FromBase64String($secret)

		# Import the newly fetched certificate on this machine and to CertStore in PFX format
		$certCollection = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
		$certCollection.Import($pfxUnprotectedBytes, $null, [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
		$pfxcertificate = $certCollection | where { $_.HasPrivateKey -eq $true }
		$pfxcertificate.FriendlyName = $certName
		$protectedCertificateBytes = $pfxcertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, "")
	 
		$newPFXCertLocation = "$UpdateCertsDir\applianceCert_$certName.pfx"       
		[System.IO.File]::WriteAllBytes($newPFXCertLocation , $protectedCertificateBytes)
		Import-PFXCertificate -CertStoreLocation Cert:\localmachine\My –Exportable -FilePath $newPFXCertLocation
			
		if (!$global:IsCertRollOverComplete -or 
		    $certName -eq "$global:DiscoveryAuthCertName")
		{		
			# Update certificate in  AAD application.
			UpdateAadApplicationCertificate $aadAppId $pfxcertificate $certString $newCert
		}

		# Delete the certificate stored on disk
		if (Test-Path $newPFXCertLocation){
			Remove-Item -Path $newPFXCertLocation -Force -ErrorAction SilentlyContinue
		}
        
    }
    catch
    {
        LogErrorAndExit "Exception: $_.Exception.Message"
    }
}

<#
.SYNOPSIS
Update all configuration files.
#>
function UpdateAllConfigFiles
{
    # Update Appliance json.
    UpdateThumbprintInConfigFile "$ApplianceJsonFilePath" "AgentAuthenticationSpn" "$global:AgentCertThumbprint" 
    UpdateThumbprintInConfigFile "$ApplianceJsonFilePath" "DiscoveryAuthenticationSpn" "$global:DiscoveryCertThumbprint"
    UpdateThumbprintInConfigFile "$ApplianceJsonFilePath" "FailbackAgentAuthenticationSpn" "$global:FailbackCertThumbprint"
    UpdateThumbprintInConfigFile "$ApplianceJsonFilePath" "MarsAgentAuthenticationSpn" "$global:MARSCertThumbprint"

    # Update Discovery json.
    UpdateThumbprintInConfigFile "$DiscoveryJsonFilePath" "AgentAuthenticationSpn" "$global:DiscoveryCertThumbprint"

    # Update Mars json.
    UpdateThumbprintInConfigFile "$MarsAgentJsonFilePath" "MarsSpnIdentity" "$global:MARSCertThumbprint"
    UpdateThumbprintInConfigFile "$MarsAgentJsonFilePath" "SpnIdentity" "$global:AgentCertThumbprint"

    # Update PushInstall json.
    UpdateThumbprintInConfigFile "$PushInstallAgentJsonFilePath" "SpnIdentity" "$global:AgentCertThumbprint"

    # Update RcmProxyAgent json.
    UpdateThumbprintInConfigFile "$RCMProxyAgentJsonFilePath" "FailbackAgentAuthenticationSpn" "$global:FailbackCertThumbprint"
    UpdateThumbprintInConfigFile "$RCMProxyAgentJsonFilePath" "SpnIdentity" "$global:AgentCertThumbprint"

    # Update RcmReplicationAgent json.
    UpdateThumbprintInConfigFile "$RcmReplicationAgentJsonFilePath" "MarsSpnIdentity" "$global:MARSCertThumbprint"
    UpdateThumbprintInConfigFile "$RcmReplicationAgentJsonFilePath" "SpnIdentity" "$global:AgentCertThumbprint"

    # Update RcmReprotectAgent json.
    UpdateThumbprintInConfigFile "$RcmReprotectAgentJsonFilePath" "SpnIdentity" "$global:FailbackCertThumbprint"

    # Update ServerDiscovery json.
    UpdateThumbprintInConfigFile "$ServerDiscoveryJsonFilePath" "AgentAuthenticationSpn" "$global:DiscoveryCertThumbprint"

    # Update ProcessServer json.
    UpdateThumbprintInConfigFile "$ProcessServerConfigFile" "RcmAzureADSpn" "$global:AgentCertThumbprint"

    # Adding Discovery json content to Appliance json.
    $DiscoveyJsonContent = Get-Content "$DiscoveryJsonFilePath" | Out-String | ConvertFrom-Json
    $ApplianceJsonContent = Get-Content "$ApplianceJsonFilePath" | Out-String | ConvertFrom-Json
    $ApplianceJsonContent.DiscoveryJson = $DiscoveyJsonContent
    $ApplianceJsonContent | ConvertTo-Json -Depth 10 | Out-String | Set-Content $ApplianceJsonFilePath
}

<#
.SYNOPSIS
Prerequisite check for .NET 4.7.2.
#>
function CheckForDotNetPrerequisite
{
    # Check for .NET version 4.7.2 or higher.
    $InstalledVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release
    Log-Info "InstalledVersion - $InstalledVersion"

    if ($InstalledVersion -ge "461808")
    {
        Log-Success ".Net version 4.7.2 or higher is installed on the machine. Proceeding ahead..."
    }
    else
    {
        LogErrorAndExit ".Net version 4.7.2 or higher is not installed on the machine. You can download the installer from https://dotnet.microsoft.com/download/dotnet-framework/net472. Aborting..."
    }
}

<#
.SYNOPSIS
Prerequisite check for Get KeyVault details.
#>
function CheckForGetKeyVaultDetails
{
    # Check for get KeyVault certificates permission.
    try
    {
        Get-AzKeyVaultCertificate -VaultName "$global:KVName"
    }
    catch 
    {
        LogErrorAndExit "Unable to get certificate details from $global:KVName Keyvault. Please check if you have the required permissions to perform the operation. Exception - $_.Exception.Message"
    }
}

<#
.SYNOPSIS
Update KeyVault with CertRollOverComplete status.
#>
function UpdateKeyVaultWithCertRollOverCompleteStatus
{
    try
    {
        $secretvalue = ConvertTo-SecureString "$global:CertRollOverStatusValue" -AsPlainText -Force
        Set-AzKeyVaultSecret -VaultName "$global:KVName" -Name "$global:CertRollOverStatusKeyName" -SecretValue $secretvalue
    }
    catch
    {
        LogErrorAndExit "Unable to add a secret key in $global:KVName Keyvault. Please check if you have the required permissions to perform the operation. Exception - $_.Exception.Message"
    }
}

<#
.SYNOPSIS
Get CertRollOverComplete status from Keyvault.
#>
function GetCertRollOverStatusFromkeyVault
{
    try
    {
        $secret = Get-AzKeyVaultSecret -VaultName "$global:KVName" -Name "$global:CertRollOverStatusKeyName" -AsPlainText
        if ($secret -eq "$global:CertRollOverStatusValue")
        {
            $global:IsCertRollOverComplete = $true
        }
    }
    catch
    {
        LogErrorAndExit "Unable to get a secret key from $global:KVName Keyvault. Please check if you have the required permissions to perform the operation. Exception - $_.Exception.Message"
    }
}

<#
.SYNOPSIS
Set directory permissions.
#>
function SetDirPermissions($dir)
{
    # Allowing access only to administartor and system. 
    icacls "$dir" /inheritance:r | Out-Null
    icacls "$dir" /grant "Administrators:(OI)(CI)F" /T | Out-Null
    icacls "$dir" /grant "SYSTEM:(OI)(CI)F" /T | Out-Null
}

##############
#### MAIN ####
##############

try
{
    Log-Info "Staring the certificate rollover process..."

    if (!(test-path $UpdateCertsDir))
    {
          New-Item -ItemType Directory -Force -Path $UpdateCertsDir
    }

    if (!(test-path $ConfigFilesBackupDir))
    {
          New-Item -ItemType Directory -Force -Path $ConfigFilesBackupDir
    }

    # Set directory permissions.
    SetDirPermissions $UpdateCertsDir

    CheckForDotNetPrerequisite

    Log-Info "Installing required PowerShell modules..."

    # Install required modules. 
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Register-PSRepository -Default -ErrorAction SilentlyContinue
	Set-PSRepository -Name PSGallery -InstallationPolicy Trusted >> $LogFile
	Install-Module -Name Az -AllowClobber -Force >> $LogFile

    GetDetailsFromApplianceConfig

    # Azure login.
    Log-Info "Please enter your login credentials to continue..."
    Connect-AzAccount -TenantId $global:TenantId
    Select-AzSubscription -SubscriptionID $global:SubscriptionID

    # Take backup of config files.
    Copy-Item -Path "$ConfigFileDir\*" -Destination "$ConfigFilesBackupDir" -Recurse -Force
    Copy-Item "$ProcessServerConfigFile" -Destination "$ConfigFilesBackupDir" -Force

    CheckForGetKeyVaultDetails

    GetCertRollOverStatusFromkeyVault

    # Stop the services.
    foreach ($Service in $ServicesList) {
        StopService -ServiceName "$Service"
    }

    # Get cert names from KeyVault.
    GetCertNamesFromKeyVault

    # Perform cert import and export operations.
    PerformCertImportExportActions $global:AgentAadAppId $global:AgentAuthCertName $global:AgentAuthCertSuffix $global:AgentSpnCertSubject

    PerformCertImportExportActions $global:DiscoveryAadAppId $global:DiscoveryAuthCertName $global:DiscoveryAuthCertSuffix $global:DiscoverySpnCertSubject
    
    PerformCertImportExportActions $global:FailbackAadAppId $global:FailbackAgentAuthCertName $global:FailbackAgentAuthCertSuffix $global:FailbackAgentSpnCertSubject

    PerformCertImportExportActions $global:MarsAgentAadAppId $global:MarsAgentAuthCertName $global:MarsAgentAuthCertSuffix $global:MarsSpnCertSubject

    UpdateKeyVaultWithCertRollOverCompleteStatus

    # Update all config files.
    UpdateAllConfigFiles

    # Update registry entries.
    UpdateRegistry -RegistryPath $DRARegistry -KeyName "AcsCertificateThumbprint" -KeyValue "$global:AgentCertThumbprint"
    UpdateRegistry -RegistryPath $MARSRegistry -KeyName "PrimaryCertThumbprint" -KeyValue "$global:MARSCertThumbprint"

    # Restart the services.
    foreach ($Service in $ServicesList) {
        RestartService -ServiceName "$Service"
    }

    # Reset IIS.
    iisreset.exe /restart | Out-Null

    Log-Success "Certificate rotated successfully."
}
catch
{
    LogErrorAndExit "Script execution failed. Exception - $_.Exception.Message"
}
# SIG # Begin signature block
# MIIhaAYJKoZIhvcNAQcCoIIhWTCCIVUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBUTx4+m5Lu+v+Y
# NX64KabMktZbJmSOXac+eFir1P9jFKCCC2YwggTuMIID1qADAgECAhMzAAAD/XwF
# Mkqq9n2uAAAAAAP9MA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTAwHhcNMjEwNDI5MTkxMjI1WhcNMjIwNDI4MTkxMjI1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC5RPGILpe8oXNeSjTTvOza/4cYCBbmAFaM3J4FpEXbRP39zLD2iDGNZU0Juh/k
# i5GtO6mEH9Yc96ytWrAl8hU9+qz07HL9j6D16bLJNlFmFCrFWdlK7gg4jgR+++ic
# TL3wUA42noIX1a/eOVhusGvoxNFR8Gh4kPltYCS73y0FPrz5p0Y/8tyNGR16AGBp
# 01ZikbJEFGku//qqkL/Ct/ZwsQ7w+sX2NngMLCfDEI5lRLyWIKeOjLO/Z0E1PfaZ
# DEOHqB/ffaWbA/F8TtytPlF/GcTXeGgi0EQwsULsBbfqFtBv+2Vq232jdB/fCt42
# GBiylQBAEhJNJT0bTWUha+E5AgMBAAGjggFtMIIBaTATBgNVHSUEDDAKBggrBgEF
# BQcDAzAdBgNVHQ4EFgQU+0IblNo4fkfR9kvvePvYhIFHKgAwUAYDVR0RBEkwR6RF
# MEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMRYw
# FAYDVQQFEw0yMzA0ODArNDY0NjA3MB8GA1UdIwQYMBaAFOb8X3u7IgBY5HJOtfQh
# dCMy5u+sMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNv
# bS9wa2kvY3JsL3Byb2R1Y3RzL01pY0NvZFNpZ1BDQV8yMDEwLTA3LTA2LmNybDBa
# BggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2kvY2VydHMvTWljQ29kU2lnUENBXzIwMTAtMDctMDYuY3J0MAwGA1Ud
# EwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAMGK9JrPdW0HVyv6qaI5qtBrfCjk
# gwwnJLVJJggvwhP61ikSkfyt84urbQFMithALf2/pIM+IdyF/DpsFEap17WabGCQ
# QWZjv0pIlG0YU2oLNNR3fOzS2iKcidShihkINQUINGEPQd+zPcG6TSjoNdNgFdV5
# lWBGrleTq0Voc5UfJNO6g1s9Oc4EtTZB9MJa6AnmeUZ9dbZLYZ3fcx9LdyOdRYoT
# 38VGuR5d3Rf6fqYfHQ7uVcNRj9MxuSMCzI+qWZMHNwjc0Zf8urlYmH3D6k4EG/hB
# xvF8Vke8qPGLuHZM9s+02kCo43+gisZfuwWd6/2Go7hX620e5sq34P2PN/wwggZw
# MIIEWKADAgECAgphDFJMAAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQg
# Um9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDYyMDQwMTda
# Fw0yNTA3MDYyMDUwMTdaMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTAw
# ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDpDmRQeWe1xOP9CQBMnpSs
# 91Zo6kTYz8VYT6mldnxtRbrTOZK0pB75+WWC5BfSj/1EnAjoZZPOLFWEv30I4y4r
# qEErGLeiS25JTGsVB97R0sKJHnGUzbV/S7SvCNjMiNZrF5Q6k84mP+zm/jSYV9Ud
# XUn2siou1YW7WT/4kLQrg3TKK7M7RuPwRknBF2ZUyRy9HcRVYldy+Ge5JSA03l2m
# pZVeqyiAzdWynuUDtWPTshTIwciKJgpZfwfs/w7tgBI1TBKmvlJb9aba4IsLSHfW
# hUfVELnG6Krui2otBVxgxrQqW5wjHF9F4xoUHm83yxkzgGqJTaNqZmN4k9Uwz5Uf
# AgMBAAGjggHjMIIB3zAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU5vxfe7si
# AFjkck619CF0IzLm76wwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0P
# BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9
# lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQu
# Y29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3Js
# MFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgZ0G
# A1UdIASBlTCBkjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAadO9XTyl7xBaFeLhQ0yL8
# CZ2sgpf4NP8qLJeVEuXkv8+/k8jjNKnbgbjcHgC+0jVvr+V/eZV35QLU8evYzU4e
# G2GiwlojGvCMqGJRRWcI4z88HpP4MIUXyDlAptcOsyEp5aWhaYwik8x0mOehR0Py
# U6zADzBpf/7SJSBtb2HT3wfV2XIALGmGdj1R26Y5SMk3YW0H3VMZy6fWYcK/4oOr
# D+Brm5XWfShRsIlKUaSabMi3H0oaDmmp19zBftFJcKq2rbtyR2MX+qbWoqaG7KgQ
# RJtjtrJpiQbHRoZ6GD/oxR0h1Xv5AiMtxUHLvx1MyBbvsZx//CJLSYpuFeOmf3Zb
# 0VN5kYWd1dLbPXM18zyuVLJSR2rAqhOV0o4R2plnXjKM+zeF0dx1hZyHxlpXhcK/
# 3Q2PjJst67TuzyfTtV5p+qQWBAGnJGdzz01Ptt4FVpd69+lSTfR3BU+FxtgL8Y7t
# QgnRDXbjI1Z4IiY2vsqxjG6qHeSF2kczYo+kyZEzX3EeQK+YZcki6EIhJYocLWDZ
# N4lBiSoWD9dhPJRoYFLv1keZoIBA7hWBdz6c4FMYGlAdOJWbHmYzEyc5F3iHNs5O
# w1+y9T1HU7bg5dsLYT0q15IszjdaPkBCMaQfEAjCVpy/JF1RAp1qedIX09rBlI4H
# eyVxRKsGaubUxt8jmpZ1xTGCFVgwghVUAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTACEzMAAAP9fAUySqr2fa4AAAAAA/0wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBDLCE8kVUetbDB9/RhOTj1N
# vhJAsNIclODgLgTSccjMMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAFfTLHHudPzR+osPG//knFO7M8LwTR7f3KmkMoimejx2RDO0TCKOzPdRT
# c2REVFwnE65SXPYQPtqgoTsoTRjlEU33iBaG6/6TFEzlRaEnjELHU6gsF1VyWBoB
# APvTEo19nVeLe2j+bdDUS69Nc75Y04GeSQLdJ5ejrLl2ux960iOg0Biy+2UjwENJ
# aSnkGUWiEcYDxrfxJqAVvPkZZFRAoU0jEkh5xxhLoSVkTM2o8BQ44TfVsG5ntEzV
# i13RsnFMfiF3GTZnexoTsvK4Usyub+14KrmKB78voX7TWyG2t3FkaLBELP9VN8vR
# ER7Ju4SNJEdhOrKMH4F5BlfuH7aM8KGCEuIwghLeBgorBgEEAYI3AwMBMYISzjCC
# EsoGCSqGSIb3DQEHAqCCErswghK3AgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCC+62XRFI/FE/JugzriMYMv3vYx06lP+0d7uMC/FA3wNQIGYYASpMY2
# GBMyMDIxMTEwODA4NTQ1OS40OTZaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo3QkYxLUUz
# RUEtQjgwODElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# DjkwggTxMIID2aADAgECAhMzAAABUcNQ51lsqsanAAAAAAFRMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIwMTExMjE4MjYw
# NFoXDTIyMDIxMTE4MjYwNFowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjdCRjEtRTNFQS1CODA4MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEF
# AAOCAQ8AMIIBCgKCAQEAn9KH76qErjvvOIkjWbHptMkYDjmG+JEmzguyr/VxjZgZ
# /ig8Mk47jqSJP5RxH/sDyqhYu7jPSO86siZh8u7DBX9L8I+AB+8fPPvD4uoLKD22
# BpoFl4B8Fw5K7SuibvbxGN7adL1/zW+sWXlVvpDhEPIKDICvEdNjGTLhktfftjef
# g9lumBMUBJ2G4/g4ad0dDvRNmKiMZXXe/Ll4Qg/oPSzXCUEYoSSqa5D+5MRimVe5
# /YTLj0jVr8iF45V0hT7VH8OJO4YImcnZhq6Dw1G+w6ACRGePFmOWqW8tEZ13SMmO
# quJrTkwyy8zyNtVttJAX7diFLbR0SvMlbJZWK0KHdwIDAQABo4IBGzCCARcwHQYD
# VR0OBBYEFMV3/+NoUGKTNGg6OMyE6fN1ROptMB8GA1UdIwQYMBaAFNVjOlyKMZDz
# Q3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9z
# b2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8yMDEwLTA3LTAx
# LmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAtMDctMDEuY3J0
# MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQEL
# BQADggEBACv99cAVg5nx0SqjvLfQzmugMj5cJ9NE60duSH1LpxHYim9Ls3UfiYd7
# t0JvyEw/rRTEKHbznV6LFLlX++lHJMGKzZnHtTe2OI6ZHFnNiFhtgyWuYDJrm7KQ
# ykNi1G1LbuVie9MehmoK+hBiZnnrcfZSnBSokrvO2QEWHC1xnZ5wM82UEjprFYOk
# chU+6RcoCjjmIFGfgSzNj1MIbf4lcJ5FoV1Mg6FwF45CijOXHVXrzkisMZ9puDpF
# jjEV6TAY6INgMkhLev/AVow0sF8MfQztJIlFYdFEkZ5NF/IyzoC2Yb9iw4bCKdBr
# dD3As6mvoGSNjCC6lOdz6EerJK3NhFgwggZxMIIEWaADAgECAgphCYEqAAAAAAAC
# MA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRo
# b3JpdHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3MDEyMTQ2NTVaMHwxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
# MIIBCgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCChfvtfGhLLF/Fw+Vh
# wna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRUQwzXTbg4CLNC3ZOs
# 1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FUsc+TTJLBxKZd0WET
# bijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBXday9ikJNQFHRD5wG
# Pmd/9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4HLDpmc085y9Euqf0
# 3GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB5jCCAeIwEAYJKwYBBAGC
# NxUBBAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvFM2hahW1VMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJ
# oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
# BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8EgZUwgZIwgY8GCSsGAQQB
# gjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL1BL
# SS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUAZwBh
# AGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG
# 9w0BAQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Prpsz1Mb7PBeKp/vpXbRkw
# s8LFZslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOMzPRgEop2zEBAQZvcXBf/
# XPleFzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCvOA8X9S95gWXZqbVr5MfO
# 9sp6AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v/rbljjO7Yl+a21dA6fHO
# mWaQjP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99lmqQeKZt0uGc+R38ONiU
# 9MalCpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1klD3ouOVd2onGqBooPiRa6
# YacRy5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQHm+98eEA3+cxB6STOvdl
# R3jo+KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30uIUBHoD7G4kqVDmyW9rI
# DVWZeodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp25ayp0Kiyc8ZQU3ghvkq
# mqMRZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HSxVXjad5XwdHeMMD9zOZN
# +w2/XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi62jbb01+P3nSISRKhggLL
# MIICNAIBATCB+KGB0KSBzTCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEm
# MCQGA1UECxMdVGhhbGVzIFRTUyBFU046N0JGMS1FM0VBLUI4MDgxJTAjBgNVBAMT
# HE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAKCi
# r3PxP6RCCyVMJSAVoMV61yNeoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDlMyK3MCIYDzIwMjExMTA4MTIxNDQ3
# WhgPMjAyMTExMDkxMjE0NDdaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOUzIrcC
# AQAwBwIBAAICCQUwBwIBAAICEYwwCgIFAOU0dDcCAQAwNgYKKwYBBAGEWQoEAjEo
# MCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG
# 9w0BAQUFAAOBgQDNZnmNOkoc7A7Y9ZuPj+i6RfuCsiOUI7gMjtaHnGAHyaJWc5a2
# PoNANgVatYaREgEFplCsU3hxO6SmqyMksE6GKWwwVW2MD5wmOm6dIOfmw5OGNI9r
# lkBr0eBVQCrt+eXLs9BVnhidkHC6R+mN8GqSaSCVZsobDsOwKxsrjevQgzGCAw0w
# ggMJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABUcNQ
# 51lsqsanAAAAAAFRMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYL
# KoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIGczItE0cEuGvMIKyIck4zeh9Wgn
# re9hsSQNK97kEBdHMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgLs1cmYj4
# 1sFZBwCmFvv9ScP5tuuUhxsv/t0B9XF65UEwgZgwgYCkfjB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMAITMwAAAVHDUOdZbKrGpwAAAAABUTAiBCBLLGMf9e17
# TloOZ6DOQcDRhWtHD0z1aLveTouCX6yK6zANBgkqhkiG9w0BAQsFAASCAQAkbdEx
# Uzd+NTJCAuFrLPJgtDAJ00mqSU54xtFCoCSkoV4XXAfpFRv1NWYfOXDvLQQ6kX/F
# cBJBfd2O9heb3n/gN6bZsXwakfX8hzkrWXgmQK3uYUikeNbCJvoFqFRZCEsnEm7w
# EUtMvQPikH/0GXLTdYxJr3aGQdu53f+e1zsHxiKWXGmpgGkpG99B3CUzYzdeX68N
# 2Rfpb3nNLx4b+22/3ctIprYmy31tJADhw41mihpMgY9+pJG1iTy/Yf0c+CVSK8pt
# 151P31UVjxFa4qfXiylYZKw9UgQ99LvO5DBh+48Bjn+4YC3qzCumFaMlzyu1vABV
# mAEWXk+5tDIOh8I+
# SIG # End signature block
