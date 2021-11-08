# Credentials Review

**How do I avoid downtime for my service?**

Ensure that you follow the steps as described in the section above and validate the new certificate works.

**What if the certificate I use is shared with other resources?**

If another application, service or resource is sharing a certificate with one of the above applications or service principals, make sure to also remove that certificate from the shared location.

**My certificate is rotated in the app/SP, but anything else I should do?**

If your certificate was issued by a trusted Certificate Authority, you must revoke the old certificate that was removed from the application or service principal.

**How can I get help?**

For any issues related to your certificate renewal or revocation, reach out to your tenant admin.

**How do I investigate any misuse of my certificate?**

Monitor the sign-in and audit logs for your application.

**What about other active credentials?**

If there are any active but unused credentials in your application or service principal, you must take action and remove the credential(s). Unused credentials are a security risk to your application.
