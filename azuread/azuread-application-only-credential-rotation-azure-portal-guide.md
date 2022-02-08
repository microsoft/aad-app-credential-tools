# Azure portal (does not work for Service principalS)

> [!Note]
> This option should only be used for application object credential rotation and does not work for Service principal credential rotation.
> To manage credentials on service principal object(s), you must use Microsoft Graph API, Microsoft Graph PowerShell modules or the Azure AD toolkit.

**(a)** Navigate to Azure Portal and switch to the relevant directory.

**(b)** Navigate to the App registration section and locate the application for which the credential needs to be rotated.

**(c)** Navigate to the “**Certificates & secrets**” blade of the app registration.

**(d)** Under the “**Certificates**” tab, click on ‘*Upload certificate*’ and follow the prompts.

**(e)** Once you are able to upload the certificate successfully, update your service code and ensure your service works with new credential and has no negative customer impact. You should use AAD’s sign-in logs to validate the thumbprint of the certificate matches to the one that was just uploaded.

**(f)** After validating the new credential, navigate back to the Certificates and Secrets blade for the app and remove the old credential.

**(g)** Review the guidance under [Credential Review](credentials-review.md) section of this document.

