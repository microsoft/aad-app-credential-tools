# Credential health assessment and update procedures for Azure AD applications and service principals

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

## Contributing

This project welcomes contributions and suggestions. Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit [https://cla.opensource.microsoft.com](https://cla.opensource.microsoft.com).

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
