**Usecase 1 - Detecting suspicious activities on existing accounts** - Keep an eye out for user accounts used to create new guest accounts with privileged roles in your tenant or any activation of the ‘Elevate Access’ operation.  
**Pre-requisite**: Microsoft CloudApps Activity log keeps track of all activities by external user accounts with administrative privileges
1) Azure connector for Azure Resources Management (ARM) events - https://docs.microsoft.com/en-us/defender-cloud-apps/connect-azure
2) Office 365 connector for AAD (Azure Active Directory) management events - https://learn.microsoft.com/en-us/defender-cloud-apps/protect-office-365#connect-office-365-to-microsoft-cloud-app-security
3) Microsoft 365 Defender onboarded 

**//Hunt for creation of new guest accounts** 

```
CloudAppEvents 
| where Timestamp > ago(7d) 
| where ActionType == "Add user." 
| where RawEventData.ResultStatus == "Success" 
| where RawEventData has "guest" and RawEventData.ObjectId has "#EXT#" 
| mv-expand Property = RawEventData.ModifiedProperties 
| where Property.Name == "AccountEnabled" and Property.NewValue has "true" 
| project Timestamp, AccountObjectId, AccountDisplayName, newGuestAccount = RawEventData.ObjectId, UserAgent
```

**//Hunt for Azure activities from guest users**

```
let newGuestAccounts = ( 
CloudAppEvents 
| where Timestamp > ago(7d) 
| where ActionType == "Add user." 
| where RawEventData.ResultStatus == "Success" 
| where RawEventData has "guest" and RawEventData.ObjectId has "#EXT#" 
| mv-expand Property = RawEventData.ModifiedProperties 
| where Property.Name == "AccountEnabled" and Property.NewValue has "true" 
| project newGuestAccountObjectId = tostring(RawEventData.Target[1].ID) 
| distinct newGuestAccountObjectId); 
CloudAppEvents 
| where Timestamp > ago(7d) 
| where isnotempty(toscalar(newGuestAccounts)) 
| where Application == "Microsoft Azure" 
| where AccountObjectId in (newGuestAccounts)
```

**//Hunt for Azure activities from high-risk users **

```
let riskyAzureSignIns = ( 
AADSignInEventsBeta 
| where Timestamp > ago(30d) 
| where ErrorCode == 0 
| where Application == "Azure Portal" 
| where RiskLevelAggregated == 100 or RiskLevelDuringSignIn == 100 
| project AccountObjectId, RiskySignInTimestamp = Timestamp); 
let AzureActivity = (  
CloudAppEvents 
| where Timestamp > ago(30d) 
| where Application == "Microsoft Azure" 
| project AccountObjectId, ActivityTime = Timestamp); 
//join the tables 
riskyAzureSignIns 
| join AzureActivity on AccountObjectId  
| where ActivityTime between (RiskySignInTimestamp .. (RiskySignInTimestamp + 12h)) 
```

Monitoring guest account privilege changes:  Be vigilant about guest accounts being promoted to privileged Microsoft Entra ID roles. Sudden privilege escalations can be a red flag for malicious activities. 
Tracking guest account modifications: Set up Kusto queries to monitor guest accounts involved in modification operations (create, update, or delete) on cloud resources. Any unauthorized changes should be investigated promptly. 
Investigating suspicious ARM activities: Pay close attention to any unusual ARM activities, especially those that deviate from expected patterns. Anomalies in resource provisioning or configuration changes may indicate a security incident. 
Identifying High-Risk sign-ins: Utilize Kusto queries to pinpoint users who have experienced 'high risk sign-ins' and have also been involved in creating resource groups. This correlation can help identify potentially compromised accounts or malicious actors within your environment. 





https://techcommunity.microsoft.com/t5/microsoft-security-experts-blog/hunting-in-azure-subscriptions/ba-p/4125875
