# Credential health assessment and update procedures for Azure AD applications and service principals

## Disclaimer

Guidance in this document applies only in relation to the mitigation steps necessary for the issue disclosed in the [CVE](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42306) and detailed in [Microsoft Security Response Center blog](https://aka.ms/CVE-2021-42306-AAD). Do not use this guidance as general credential rotation procedure.

## Assessment

There are a few ways by which you can find if the credential(s) on your application or service principal need to be rotated.

| **Assessment method**                             | **Credential assessment guide**                                                                                   |
| -------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| KeyCredential assessment using MS Graph API  (recommended)               | [Application credential assessment using MS Graph API](azuread-application-credential-assessment-msgraph-guide.md)                   |
| KeyCredential assessment PowerShell module for MS Graph API               | [Application credential assessment PowerShell module](azuread-application-credential-assessment-powershell-guide.md)                   |
| Azure Sentinel (license required)                | [Application credential assessment using Azure Sentinel notebook](azuread-application-credential-assessment-sentinel-guide.md)                   |

## Remediation

Application or service principal credentials can be rotated using one of the following options.
You may use any one of the 3 options but ensure that you follow the steps as described for each option to avoid any downtime.
The steps detailed below will help you add a new credential to the application object and remove instances of previous credentials identified by the key cred scanner tool.
If the credential that needs to be rotated is expired, you can skip the steps to add a certificate and jump to the certificate removal section.

| **Rotation method**                             | **Credential rotation guide**                                                                                   |
| -------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Azure AD Toolkit for applications and service principals (recommended)               | [Application credential rotation using Azure AD Toolkit](azuread-application-credential-rotation-azuread-toolkit-guide.md)                   |
| MS Graph application and service principal APIs                 | [Application credential rotation using MS Graph API](azuread-application-credential-rotation-msgraph-guide.md)                   |
| Azure portal (for application object only)                 | [Application only credential rotation using Azure portal](azuread-application-only-credential-rotation-azure-portal-guide.md)                   |

