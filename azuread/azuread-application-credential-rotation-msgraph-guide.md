# Application credential rotation using MS Graph API

**Artifacts**

**(a)** Application object: `https://graph.microsoft.com/v1.0/applications/{object-Id}`

**(b)** Service Principal object: `https://graph.microsoft.com/v1.0/serviceprincipals/{object-Id}`

**Steps:**

1. List all credentials on the Application object
    a. Get the application metadata by calling the app API `https://graph.microsoft.com/v1/applications/{objectId}?$select=keyCredentials`.
    b. From the response that contains keyCredential information, copy keyCredentials property data to a notepad. This information needs to be sent back to the server along with the new certificate credential being added.

2. Add a new certificate (x509) credential to the Application object creating a PATCH request on the application object

**Sample request:**

```json
PATCH https://graph.microsoft.com/v1.0/applications/0ff09dad-3c7c-4a66-bc2b-7bbb45763a60 
```

PATCH body:

```json
{
    "keyCredentials": [{
            "type": "AsymmetricX509Cert",
            "usage": "Verify",
            "startDateTime": "2021-05-25T00:13:08Z",
            "endDateTime": "2022-05-25T00:13:08Z",
            "key": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlEU…"
        },
        {
            "customKeyIdentifier": "A3F0F2A04A5556CE3FEFF4A0CCB47905AC7C66E4",
            "displayName": "CN=*.mylocaltest ",
            "endDateTime": "2021-11-12T21:51:40Z",
            "key": null,
            "keyId": "88a9542c-3a26-4136-b571-9d69acae98b2",
            "startDateTime": "2021-10-12T21:41:40Z",
            "type": "AsymmetricX509Cert",
            "usage": "Verify"
        },
        {
            "customKeyIdentifier": "7A28B6653D0319E69D27E74580E7C91D765AF867",
            "displayName": "CN=MyDevCert",
            "endDateTime": "2021-05-21T03:35:32Z",
            "key": null,
            "keyId": "7a2ac168-ad65-46f4-95d6-b03f183974d3",
            "startDateTime": "2020-05-21T03:15:32Z",
            "type": "AsymmetricX509Cert",
            "usage": "Verify"
        }
    ]
}
```

3. Update your service code and ensure your service works with new credential and has no negative customer impact. You should use AAD’s sign-in logs to validate the thumbprint of the certificate matches to the one that was just uploaded.

4. Remove the old KeyId value(s) recorded in step 1.b. by making a PATCH request to the applications endpoint. Before making a PATCH request to remove the credential, you will need to make a GET request and GET all credential. This will ensure that your existing new credential or any other valid credentials do not get removed when you create a PATCH request. 

**Sample request:**

```html
GET https://graph.microsoft.com/v1.0/applications/0ff09dad-3c7c-4a66-bc2b-7bbb45763a60/keyCredentials 
```

**Response:**

```json
 {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#applications('51603b67-f038-4667-93bb-1dce786ef7b0')/keyCredentials",
    "value": [{
            "customKeyIdentifier": "7A28B6653D0319E69D27E74580E7C91D765AF867",
            "displayName": "CN=MyDevCert",
            "endDateTime": "2021-05-21T03:35:32Z",
            "key": null,
            "keyId": "76a25311-2a8d-4539-b125-53093bb93e18",
            "startDateTime": "2020-05-21T03:15:32Z",
            "type": "AsymmetricX509Cert",
            "usage": "Verify"
        },
        {
            "customKeyIdentifier": "A3F0F2A04A5556CE3FEFF4A0CCB47905AC7C66E4",
            "displayName": "CN=*.mylocaltest.com",
            "endDateTime": "2021-11-12T21:51:40Z",
            "key": null,
            "keyId": "88a9542c-3a26-4136-b571-9d69acae98b2",
            "startDateTime": "2021-10-12T21:41:40Z",
            "type": "AsymmetricX509Cert",
            "usage": "Verify"
        }
    ]
}
```

Create a PATCH request and send all the data back, except for the credential that needs to be removed. 

```json
PATCH  https://graph.microsoft.com/v1.0/applications/0ff09dad-3c7c-4a66-bc2b-7bbb45763a60/keyCredentials 
```

PATCH body:

```json
 {
    "keyCredentials": [{
            "customKeyIdentifier": "7A28B6653D0319E69D27E74580E7C91D765AF867",
            "displayName": "CN=MyDevCert",
            "endDateTime": "2021-05-21T03:35:32Z",
            "key": null,
            "keyId": "76a25311-2a8d-4539-b125-53093bb93e18",
            "startDateTime": "2020-05-21T03:15:32Z",
            "type": "AsymmetricX509Cert",
            "usage": "Verify"
        },
        {
            "customKeyIdentifier": "A3F0F2A04A5556CE3FEFF4A0CCB47905AC7C66E4",
            "displayName": "CN=*.mylocaltest.com",
            "endDateTime": "2021-11-12T21:51:40Z",
            "key": null,
            "keyId": "88a9542c-3a26-4136-b571-9d69acae98b2",
            "startDateTime": "2021-10-12T21:41:40Z",
            "type": "AsymmetricX509Cert",
            "usage": "Verify"
        }
    ]
}
```

5. Repeat steps 1-4 for Service Principal object(s) associated with the above application.

6. Use the AAD key cred scanner PowerShell module or MS Graph API to ensure your newly added credential does not contain any private key information.

7. Review the guidance under [Credential Review](credentials-review.md) document.

> [!Note]
> You can also achieve the desired key rotation results by following the steps described above by using [MS Graph PowerShell modules](https://docs.microsoft.com/en-us/graph/powershell/installation?context=graph%2Fapi%2F1.0&view=graph-rest-1.0).

