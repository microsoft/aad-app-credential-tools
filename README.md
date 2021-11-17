# Credential health assessment and update procedures for Azure Automation, Azure Migrate, Azure Site Recovery and Azure AD applications

The following doc walks through various options and process of assessment and rotation of keyCredentials (certificates) for applications and service principal objects (Apps/SPs) created by services such as Azure Automation, Azure Migrate, Azure Site Recovery. Applications created via other mechanisms might need to rotate their credentials if your tenant admin identified a credential on your application as needing attention.

Azure AD application needing credential rotation could have been created by `Azure Automation Service`, `Azure Migrate Service`, `Azure Site Recovery` or manually using the Azure portal.
To pick the right remediation guidance, you must pick the assessment script for the one of these services. If one or more of these services are used in your organization, you will need to run through the assessment script for each of the services.  This will ensure you are able to pick the right guidance and avoid downtime for your app/service.
The following table can help identify the type of service that created the Azure AD application.

| Service type                                | Ways to identify app association                                                                                                                                                    |
| -------------------------| ------------------------------------------------------------------------------------------------------------------------------------ |
| Azure Automation Service | For Automation, the signInUrl in manifest has the URL to automation account which signifies the application is associated with an Automation account. You can find your application manifest under the App registration section in Azure portal.|
| Azure Migrate Service    | Under the App registration section in Azure AD portal, the applications associated with Azure Migrate contain one of the following suffixes: `resourceaccessaadapp`,`agentauthaadapp`,`authandaccessaadapp` |
| Azure Site Recovery      | For Site Recovery, applications in Azure portal under the App registration section Azure AD app would have one of the following suffix - `authandaccessaadapp`, `marsauthaadapp`, `failbackagentauthaadapp`, `discoveryauthaadapp`  |

> [!Note]
> For Azure AD applications or service principals not created by one of the above services, following the assessment and remediation guide for Azure AD applications and Service principals listed below.

## Assessment and remediation

| Product/Service                              | Assessment guide                                                                                         |
| -------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Azure Automation                             | [Azure Automate credential assessment and remediation guidance](/azure-automation/azure-automation-runas-credential-remediation.md)                   |
| Azure Migrate                                | [Azure Migrate credential assessment and remediation guide](/azure-migrate/azure-migrate-credential-rotation-guide.md)                     |
| Azure Site Recovery                          | [Azure Site Recovery credential assessment and remediation guide](/azure-site-recovery/azure-site-recovery-credential-rotation-guide.md)          |
| Azure AD Applications and Service principals | [Azure AD Application/Service principal assessment and remediation guide](/azuread/azuread-app-credential-remediation-guide.md) |

## Disclaimer

Guidance in these documents applies only in relation to the mitigation steps necessary for the issue disclosed in the [CVE](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42306) and detailed in [Microsoft Security Response Center blog](https://aka.ms/CVE-2021-42306-AAD). Do not use this guidance as general credential rotation procedure.

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
