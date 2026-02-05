# HelloID-Conn-SA-Full-EntraID-AccountDisable

| :information_source: Information |
| :------------------------------- |
| This repository contains the connector and configuration code only. The implementer is responsible for acquiring the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements. |

## Description
HelloID-Conn-SA-Full-ExchangeOnline-SharedMailbox-Permissions is a template designed for use with HelloID Service Automation (SA) Delegated Forms. It can be imported into HelloID and customized according to your requirements.

By using this delegated form, you can manage shared mailbox permissions in Exchange Online. The following options are available:
 1. Search and select the shared mailbox (wildcard search supported)
 2. Choose the permission type:
    - Full Access
    - Send As
    - Send on Behalf
 3. Add or remove users from the selected permission via a dual list
 4. Submit the form to apply the changes in Exchange Online

Notes shown in the form:
- Retrieving mailboxes typically takes ~10 seconds
- Retrieving mailbox permissions typically takes ~30 seconds

## Getting started
### Requirements

#### App Registration & Certificate Setup

Before implementing this connector, make sure to configure a Microsoft Entra ID, an App Registration. During the setup process, you’ll create a new App Registration in the Entra portal, assign the necessary API permissions (such as user and group read/write), and generate and assign a certificate.

Follow the official Microsoft documentation for creating an App Registration and setting up certificate-based authentication:
- [App-only authentication with certificate (Exchange Online)](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps#set-up-app-only-authentication)

#### HelloID-specific configuration

Once you have completed the Microsoft setup and followed their best practices, configure the following HelloID-specific requirements.

- **API Permissions** (Application permissions):
  - `User.ReadWrite.All`
  - `Group.ReadWrite.All`
  - `GroupMember.ReadWrite.All`
  - `UserAuthenticationMethod.ReadWrite.All`
  - `User.EnableDisableAccount.All`
  - `User-PasswordProfile.ReadWrite.All`
  - `User-Phone.ReadWrite.All`
  - **Entra ID Role assignment:**
  - Assign the **Exchange Recipient Administrator** role to the App Registration
- **Certificate:**
  - Upload the public key file (.cer) in Entra ID
  - Provide the certificate as a Base64 string in HelloID. For instructions on creating the certificate and obtaining the base64 string, refer to our forum post: [Setting up a certificate for Microsoft Graph API in HelloID connectors](https://forum.helloid.com/forum/helloid-provisioning/5338-instruction-setting-up-a-certificate-for-microsoft-graph-api-in-helloid-connectors#post5338)

### Connection settings

The following user-defined variables are used by the connector.

| Setting     | Description                              | Mandatory |
| ----------- | ---------------------------------------- | --------- |
| EntraTenantId | Entra tenant ID                       | Yes       |
| EntraAppId    | Entra application (client) ID         | Yes       |
| EntraCertificateBase64String | Entra Certificate string      | Yes       |
| EntraCertificatePassword | Entra Certificate password      | Yes       |

## Remarks

- Mailbox search:
  - When no search value or `*` is provided, all mailboxes are retrieved.
- Permission management scope:
  - The form manages user assignments for `Full Access`, `Send As`, and `Send on Behalf`.
- Dual list behavior:
  - Left list shows available users; right list shows current assignments for the selected mailbox and permission.
- Performance notes:
  - Retrieving mailboxes typically takes ~10 seconds; permissions ~30 seconds.
- Duplicate import:
  - When importing a duplicate form, resource names can be suffixed automatically, as configured in the script.

## Development resources

### API endpoints

This connector uses Exchange Online PowerShell (EXO) cmdlets via the `ExchangeOnlineManagement` module:

| Cmdlet/Operation                     | Description                                        |
| ------------------------------------ | -------------------------------------------------- |
| Get-EXOMailbox                       | Search and retrieve shared mailboxes               |
| Get-EXOMailboxPermission             | Retrieve Full Access permissions                    |
| Add/Remove-EXOMailboxPermission      | Grant/Remove Full Access                           |
| Get-EXORecipientPermission           | Retrieve Send As permissions                        |
| Add/Remove-EXORecipientPermission    | Grant/Remove Send As                               |
| Set-EXOMailbox (GrantSendOnBehalfTo) | Manage Send on Behalf assignments                   |

### API documentation

- Exchange Online PowerShell overview: https://learn.microsoft.com/powershell/exchange/exchange-online-powershell
- Mailbox permissions (Full Access): https://learn.microsoft.com/powershell/module/exchange/get-mailboxpermission
- Recipient permissions (Send As): https://learn.microsoft.com/powershell/module/exchange/add-recipientpermission
- Mailbox settings (Send on Behalf): https://learn.microsoft.com/powershell/module/exchange/set-mailbox

## Getting help
> :bulb: **Tip:**  
> For more information on Delegated Forms, please refer to our documentation pages: https://docs.helloid.com/en/service-automation/delegated-forms.html

## HelloID docs
The official HelloID documentation can be found at: https://docs.helloid.com/
