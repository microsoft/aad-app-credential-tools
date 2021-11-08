# Azure Sentinel notebook

Microsoft Sentinel team has a notebook **<Link>** that will help identify the applications/service principals and their credentials that need rotation. The notebook uses the key credential property of the Microsoft Graph API to find the AppId’s in a tenant and adds them to a watchlist in Microsoft Sentinel. It then references the generated watchlist to look for anomalous Service Principal logins as well as potentially malicious activities by the impacted apps. Additional context for suspicious IP addresses that are surfaced in the queries is provided using the  `msticpy` package.  In addition to the notebooks, customers can also find the apps requiring credential rollover using Microsoft Sentinel playbook **<LINK>**.

If you are ingesting AAD Audit/AzureActivity logs in your Microsoft Sentinel instance you can try looking for potential malicious activity involving the impacted apps. For hunting purposes, we can use the AppId’s in the generated watchlist above and look for possible anomalous Service Principal logins using location as a pivot (below query). Generally speaking, a lot of the Service principal logging usually happens from a few known locations/IP ranges – this might be a known IP address range for Azure or from an known IP range/location of an on-premises datacenter. We try to use this as a hunting logic in the below query. Results of IP/Location based hunting queries can sometimes be noisy and hence environment-based specifics needs to be factored in when using the results in an investigation.

``` SQL
let watchlist = (_GetWatchlist('Vulnerable_CVE_2021_42306') | project AppId);  
let appID_city_dcount = AADServicePrincipalSignInLogs 
| where AppId in (watchlist)     
| where ResultType == 0
| extend LocationDetails = todynamic(LocationDetails)
| where isnotempty(tostring(LocationDetails["city"]))
| extend Locale = strcat(tostring(LocationDetails["city"]), '|', tostring(LocationDetails['state']), '|', tostring(LocationDetails['countryOrRegion']))
| summarize Locale_dcount = dcount(tostring(Locale)) by AppId, key=1.5;
let avgAppId = appID_city_dcount | summarize avg(Locale_dcount) by key;
//get only 50% greater than average or more for city count/ key value above is == 1.5, adjust as needed
let anomAppId = appID_city_dcount | lookup avgAppId on key | where Locale_dcount > key*avg_Locale_dcount | project-away key, Locale_dcount, avg_Locale_dcount;
AADServicePrincipalSignInLogs
| where AppId in (anomAppId)
| extend LocationDetails = todynamic(LocationDetails)
| where isnotempty(tostring(LocationDetails["city"]))
| extend Locale = strcat(tostring(LocationDetails["city"]), '|', tostring(LocationDetails['state']), '|', tostring(LocationDetails['countryOrRegion']))
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), make_set(IPAddress), dcount(IPAddress), make_set(ServicePrincipalId), make_set(Locale), dcount(Locale) by AppId, ResourceDisplayName, ServicePrincipalName, ResourceIdentity
```
 The IP addresses/ AppId’s surfaced from the above query should be verified if they look anomalous considering the specifics of the environment. The interesting IP/AppId can be used in the queries below to find additional activities using the AzureActivity logs and AuditLogs. While AzureActivity logs provides insight into subscription-level events like when a resource is modified or when a virtual machine is started etc. the AuditLogs provide information about user and group management, managed applications and directory activities that happened from suspicious IP’s.

```sql
// add the list of suspicious IP’s here
let IP = dynamic(["a.a.a.a", "x.x.x.x"]);
// add the list of suspicious AppID from the previous query here
let ApplicationId = dynamic(["12345-xxxx-4af5-bea0-81646d475a49"]);
AADServicePrincipalSignInLogs
| where IPAddress in (IP)              
| where AppId in (ApplicationId)   
| join kind = inner   
( 
 AzureActivity
| where isnotempty(Claims_d.appid)
| extend AppId = tostring(Claims_d.appid) , Claims_d.uti == tostring(Claims_d.uti)
| extend uti = replace_regex(tostring(Claims_d.uti), '$', '==')
| extend uti = replace_regex(uti, '-', '+')
| extend uti = replace_regex(uti, '_', '/')
| extend uti = base64_decode_toguid(uti)
| extend Id = tostring(uti)
) on Id, AppId, $left.IPAddress == $right.CallerIpAddress
| project TimeInActivityLog = TimeGenerated, TimeInSPNLog = TimeGenerated1, ResourceGroup, ServicePrincipalId, ServicePrincipalName, OperationNameValue, IPAddress,AppId, ResourceDisplayName, activityResource = tostring(Claims_d.aud), tostring(parse_json(Authorization).evidence.role), _ResourceId, LocationDetails, Properties_d, ResourceGroupActivityLog = ResourceGroup1, SubscriptionId,Id
```

```sql
// add the list of suspicious IP’s here                                                     
 
let IP = dynamic(["a.a.a.a", "x.x.x.x"]);
// add the list of suspicious AppID from the previous query here
let ApplicationId = dynamic(["12345-xxxx-4af5-bea0-81646d475a49"]);
AADServicePrincipalSignInLogs
| where IPAddress in (IP)  
| where AppId in (ApplicationId)  
| join kind = inner
( AuditLogs 
| extend ServicePrincipalId = tostring(parse_json(tostring(InitiatedBy.app)).servicePrincipalId)
) on ServicePrincipalId
```
