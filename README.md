# HelloID-Conn-SA-Full-Exchange-Online-MailboxPermissionsUpdate

| :information_source: Information                                                                                                                                                                                                                                                                            |
| :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| This repository contains the connector and configuration code only. The implementer is responsible for acquiring the connection details such as organization name, application ID, certificate, etc. You might need to coordinate with the client's application manager before implementing this connector. |

## Description

HelloID-Conn-SA-Full-Exchange-Online-MailboxPermissionsUpdate is a delegated form designed for use with HelloID Service Automation (SA). It can be imported into HelloID and customized according to your requirements.

By using this delegated form, you can manage shared mailbox permissions in Exchange Online. The following options are available:

1. Search and select a shared mailbox (wildcard search by name and email addresses)
2. Select the permission type to manage (Full Access, Send As, or Send on Behalf)
3. Add or remove users from the selected permission via a dual list
   > The left part of the dual list shows all available users  
   > The right part of the dual list shows the users who currently have the selected permission  
4. grant or revoke the selected permission for multiple users to or from the selected mailbox
   > Users moved to the left part of the dual list will have their permission revoked  
   > Users moved to the right part of the dual list will have their permission granted  

## Getting started
### Requirements

#### App Registration & Certificate Setup

Before implementing this connector, make sure to configure a Microsoft Entra ID App Registration. During the setup process, you'll create a new App Registration in the Entra portal, assign the necessary API permissions, and generate and assign a certificate.

Follow the official Microsoft documentation for creating an App Registration and setting up certificate-based authentication:
- [App-only authentication with certificate (Exchange Online)](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps#set-up-app-only-authentication)

#### HelloID-specific configuration

Once you have completed the Microsoft setup and followed their best practices, configure the following HelloID-specific requirements.

- **API Permissions** (Application permissions):
  - `User.Read.All` - To list all users via Graph API for the dual list
  - `Exchange.ManageAsApp` - To manage mailbox permissions
- **Entra ID Role assignment:**
  - Assign the **Exchange Administrator** role to the App Registration
- **Certificate:**
  - Upload the public key file (.cer) in Entra ID
  - Provide the certificate as a Base64 string in HelloID. For instructions on creating the certificate and obtaining the base64 string, refer to our forum post: [Setting up a certificate for Microsoft Graph API in HelloID connectors](https://forum.helloid.com/forum/helloid-provisioning/5338-instruction-setting-up-a-certificate-for-microsoft-graph-api-in-helloid-connectors#post5338)

### Connection settings

The following global variables must be configured in HelloID when importing and configuring the delegated form.

| Setting                        | Description                                                              | Mandatory |
| ------------------------------ | ------------------------------------------------------------------------ | --------- |
| EntraIdOrganization            | The Entra organization name (domain)                                     | Yes       |
| EntraIdTenantId                | The unique identifier (ID) of your Entra ID tenant                       | Yes       |
| EntraIdAppId                   | The unique identifier (ID) of the App Registration in Microsoft Entra ID | Yes       |
| EntraIdCertificateBase64String | The Base64-encoded string representation of the app certificate          | Yes       |
| EntraIdCertificatePassword     | The password associated with the app certificate                         | Yes       |

## Remarks

### Performance Optimization Strategy

The connector prioritizes the use of Microsoft Graph API over Exchange Online PowerShell cmdlets wherever possible. The Graph API is significantly faster for data retrieval (Exchange Online cmdlets like `Get-Mailbox` or `Get-User` can take 30+ seconds per query, while Graph API typically responds in under a second). However, certain Exchange-specific data and operations are not available via Graph API and still require the Exchange Online module.

### Where Graph API is Used

**User object retrieval** (dual list - left side):
- All available users are retrieved from Microsoft Graph API
- Filter: `$filter=userType eq 'Member'` (excludes guest users)
- Properties returned: `id`, `userPrincipalName`, `displayName`, `mail`
- **Why Graph API**: Fastest method to retrieve user objects with filtering capabilities

**User object enrichment** (dual list - right side):
- After retrieving permission assignments from Exchange Online, the actual user objects are queried via Microsoft Graph API
- **Why Graph API**: Significantly faster than using Exchange Online cmdlets to retrieve user details

### Where Exchange Online Module is Still Required

**Shared mailbox search**:
- Uses `Get-EXORecipient` cmdlet to search for shared mailboxes
- When `*` is provided as search value, all shared mailboxes are retrieved
- Supports wildcard search on both mailbox name and email addresses
- Filter applied: `(Name -like '*$searchValue*' -or EmailAddresses -like '*$searchValue*') -and RecipientTypeDetails -eq 'SharedMailbox'`
- **Why Exchange Online**: Graph API doesn't support filtering by recipient type (e.g., cannot query shared mailboxes specifically, only all mailbox-enabled objects)
- **Note**: `Get-EXORecipient` is used instead of `Get-Mailbox` for faster retrieval within the Exchange Online module

**Permission assignment retrieval** (dual list - right side):
- Permission assignments are retrieved from Exchange Online as mailbox permissions are not exposed via Graph API
- For **Full Access**: Uses `Get-MailboxPermission` cmdlet
- For **Send As**: Uses `Get-RecipientPermission` cmdlet
- For **Send on Behalf**: Uses `Get-EXOMailbox` cmdlet (reads GrantSendOnBehalfTo property)
- **Why Exchange Online**: Mailbox permissions (Full Access, Send As, Send on Behalf) are not available via Microsoft Graph API

## Development resources

### API endpoints

The following Microsoft Graph API endpoints are used by the connector for user listing:

| Endpoint      | Description                                                  |
| ------------- | ------------------------------------------------------------ |
| `/v1.0/users` | Retrieve all users (excluding guest users) for the dual list |

### PowerShell Cmdlets

The following PowerShell cmdlets are used by the connector:

| Cmdlet                       | Description                                                                          |
| ---------------------------- | ------------------------------------------------------------------------------------ |
| `Connect-ExchangeOnline`     | Establish session to Exchange Online using certificate-based app-only authentication |
| `Get-Recipient`              | Search for shared mailboxes                                                          |
| `Get-EXORecipient`           | Search for shared mailboxes (optimized version)                                      |
| `Get-Mailbox`                | Retrieve mailbox details                                                             |
| `Get-EXOMailbox`             | Retrieve mailbox details (optimized version)                                         |
| `Get-MailboxPermission`      | Retrieve Full Access permissions for a mailbox                                       |
| `Add-MailboxPermission`      | Grant Full Access permission to a user                                               |
| `Remove-MailboxPermission`   | Revoke Full Access permission from a user                                            |
| `Get-RecipientPermission`    | Retrieve Send As permissions for a mailbox                                           |
| `Add-RecipientPermission`    | Grant Send As permission to a user                                                   |
| `Remove-RecipientPermission` | Revoke Send As permission from a user                                                |
| `Set-Mailbox`                | Configure Send on Behalf permissions (grant or revoke)                               |
| `Disconnect-ExchangeOnline`  | Close the Exchange Online session                                                    |

### Documentation

For more information on the APIs and PowerShell cmdlets used in this connector, please refer to:

**Microsoft Graph API:**
- [Authentication with certificate](https://learn.microsoft.com/graph/auth-v2-service)
- [List users - Advanced query capabilities](https://learn.microsoft.com/graph/aad-advanced-queries)
- [User resource reference](https://learn.microsoft.com/graph/api/user-list)

**Exchange Online PowerShell:**
- [Exchange Online PowerShell overview](https://learn.microsoft.com/powershell/exchange/exchange-online-powershell)
- [Connect-ExchangeOnline](https://learn.microsoft.com/powershell/module/exchange/connect-exchangeonline)
- [Get-Recipient](https://learn.microsoft.com/powershell/module/exchange/get-recipient)
- [Get-EXORecipient](https://learn.microsoft.com/powershell/module/exchange/get-exorecipient)
- [Get-Mailbox](https://learn.microsoft.com/powershell/module/exchange/get-mailbox)
- [Get-EXOMailbox](https://learn.microsoft.com/powershell/module/exchange/get-exomailbox)
- [Get-MailboxPermission](https://learn.microsoft.com/powershell/module/exchange/get-mailboxpermission)
- [Add-MailboxPermission](https://learn.microsoft.com/powershell/module/exchange/add-mailboxpermission)
- [Remove-MailboxPermission](https://learn.microsoft.com/powershell/module/exchange/remove-mailboxpermission)
- [Get-RecipientPermission](https://learn.microsoft.com/powershell/module/exchange/get-recipientpermission)
- [Add-RecipientPermission](https://learn.microsoft.com/powershell/module/exchange/add-recipientpermission)
- [Remove-RecipientPermission](https://learn.microsoft.com/powershell/module/exchange/remove-recipientpermission)
- [Set-Mailbox](https://learn.microsoft.com/powershell/module/exchange/set-mailbox)
- [Disconnect-ExchangeOnline](https://learn.microsoft.com/powershell/module/exchange/disconnect-exchangeonline)

## Getting help

> 💡 **Tip:**  
> For more information on Delegated Forms, please refer to our [documentation](https://docs.helloid.com/en/service-automation/delegated-forms.html) pages.

## HelloID docs

The official HelloID documentation can be found at: [https://docs.helloid.com/](https://docs.helloid.com/)
