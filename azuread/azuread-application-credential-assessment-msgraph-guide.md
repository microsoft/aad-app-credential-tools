# MS Graph API (recommended)

You can use MS Graph application and service principal APIs to get the application or service principal resources that need to be assessed. The keyCredential object in the application api has a new property ‘hasExtendedValue’ which indicates the need to rotate the credential. The following points are crucial to conducting an accurate assessment for your applications.

- The call to get an application or service principal requires the use of **`$select`** query parameter to get accurate result for the **`hasExtendedValue`** property.
- If the APIs are called without the query parameters, the property `hasExtendedValue` will default to null and should not be interpreted as a false.
- For a given credential if the value of `hasExtendedValue` is true, it signifies the presence of private key data and that keyCredential must be rotated.
- The property is available only in the MS Graph beta endpoint.
- This new property will not be part of the MS Graph beta schema.

Here are the details of the request and sample response:

## Request details

**Method**: GET

**Application/Service Principal api**:

`https://graph.microsoft.com/beta/applications/{id}?$select=keyCredentials` **or**

`https://graph.microsoft.com/beta/servicePrincipals/{id}?$select=keyCredentials`

**Payload Property**: hasExtendedValue

**Payload property type**: Boolean (nullable)

## Response details

**Sample response**:

```json
{
    "@odata.context": "https://graph.microsoft.com/beta/$metadata#applications(keyCredentials)/$entity",
    "keyCredentials": [
        {
            "customKeyIdentifier": "7A28B6653D0319E69D27E74580E7C91D765AF867",
            "endDateTime": "2021-05-21T03:35:32Z",
            "keyId": "772faab4-9b59-456e-b73e-baadbfa4b92d",
            "startDateTime": "2020-05-21T03:15:32Z",
            "type": "AsymmetricX509Cert",
            "usage": "Verify",
            "key": "MIIDKzCC……",
            "displayName": "CN=MyCert",
            "hasExtendedValue": false
        }
    ]
}
```
