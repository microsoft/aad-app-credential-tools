# Azure AD Toolkit PowerShell module (Recommended)

**a)** Install the module by running `Install-Module AzureADToolkit`

**b)** Connect to the tenant `Connect-AADToolkit -TenantId <TenantId-GUID>`

**c)** Run `Update-AADToolkitApplicationCredentials`

**d)** Pick option #1 to add a new credential and follow the prompts. Ensure that you are adding only the public key value of the cert and no private key information is attached to the cert.

**e)** Update your service code and confirm the new credential works. Ensure the thumbprint of the new certificate shows in the sign-in logs.

**f)** Review the guidance under [Credential Review](credentials-review.md) document.

**g)** Switch back to Toolkit and remove the old certificate by selecting option #4.

**h)** Monitor error logs for any errors post credential rotation.
