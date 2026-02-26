# variables configured in form
$mailbox = $form.gridMailbox
$permission = $form.permission
$usersToAdd = $form.permissionList.leftToRight
$usersToRemove = $form.permissionList.rightToLeft

# Global variables
# Outcommented as these are set from Global Variables
# $EntraIdOrganization = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# Fixed values
$commands = @(
    "Add-MailboxPermission",
    "Add-RecipientPermission",
    "Set-Mailbox",
    "Remove-MailboxPermission",
    "Remove-RecipientPermission"
)

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

#region functions
function Get-MSEntraCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CertificateBase64String,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CertificatePassword
    )
    try {
        $rawCertificate = [system.convert]::FromBase64String($CertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
#endregion functions

try {
    # Import module
    $actionMessage = "importing module [ExchangeOnlineManagement]"
        
    $importModuleSplatParams = @{
        Name        = "ExchangeOnlineManagement"
        Cmdlet      = $commands
        Verbose     = $false
        ErrorAction = "Stop"
    }

    $null = Import-Module @importModuleSplatParams

    Write-Verbose "Imported module [ExchangeOnlineManagement]"

    # Convert base64 certificate string to certificate object
    $actionMessage = "converting base64 certificate string to certificate object"

    $certificate = Get-MSEntraCertificate -CertificateBase64String $EntraIdCertificateBase64String -CertificatePassword $EntraIdCertificatePassword

    Write-Verbose "Converted base64 certificate string to certificate object"

    # Connect to Microsoft Exchange Online
    # Docs: https://learn.microsoft.com/en-us/powershell/module/exchange/connect-exchangeonline?view=exchange-ps
    $actionMessage = "connecting to Microsoft Exchange Online"

    $createExchangeSessionSplatParams = @{
        Organization          = $EntraIdOrganization
        AppID                 = $EntraIdAppId
        Certificate           = $certificate
        CommandName           = $commands
        ShowBanner            = $false
        ShowProgress          = $false
        TrackPerformance      = $false
        SkipLoadingCmdletHelp = $true
        SkipLoadingFormatData = $true
        ErrorAction           = "Stop"
    }

    $null = Connect-ExchangeOnline @createExchangeSessionSplatParams

    # Grant users permissions to shared mailbox
    $actionMessage = "granting permission [$permission] to shared mailbox to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for users"
    foreach ($userToAdd in $usersToAdd) {
        switch ($permission) {
            "fullaccess" {
                # Grant Full Access to shared mailbox
                try {
                    $actionMessage = "granting permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.userPrincipalName) ($($userToAdd.id))]"

                    $FullAccessPermissionSplatParams = @{
                        Identity      = $mailbox.guid  # of $mailbox.UserPrincipalName
                        User          = $userToAdd.id
                        AccessRights  = "FullAccess"
                        AutoMapping   = [bool]$AutoMapping
                        ErrorAction   = "Stop"
                        WarningAction = "SilentlyContinue"
                    }
                    $addFullAccessPermission = Add-MailboxPermission @FullAccessPermissionSplatParams

                    # Send auditlog to HelloID
                    $Log = @{
                        Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                        System            = "Exchange" # optional (free format text) 
                        Message           = "Successfully granted permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.userPrincipalName) ($($userToAdd.id))]" # required (free format text) 
                        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = $mailbox.DisplayName # optional (free format text)
                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
                    }
                    Write-Information -Tags "Audit" -MessageData $log
                }
                catch {
                    $ex = $PSItem
                    if (-not [string]::IsNullOrEmpty($ex.Exception.Data.RemoteException.Message)) {
                        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Data.RemoteException.Message)"
                        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Data.RemoteException.Message)"
                    }
                    else {
                        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
                        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
                    }

                    $Log = @{
                        Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                        System            = "ExchangeOnline" # optional (free format text) 
                        Message           = $auditMessage # required (free format text) 
                        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = $mailboxDisplayName # optional (free format text) 
                        TargetIdentifier  = $mailboxPrimarySmtpAddress # optional (free format text) 
                    }
                    Write-Information -Tags "Audit" -MessageData $log
                    Write-Warning $warningMessage
                    Write-Error $auditMessage
                }
                break
            }
            
            "sendas" {
                # Grant Send As to shared mailbox
                try {
                    $actionMessage = "granting permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.userPrincipalName) ($($userToAdd.id))]"

                    $sendAsPermissionSplatParams = @{
                        Identity     = $mailbox.Guid
                        Trustee      = $userToAdd.id
                        AccessRights = "SendAs"
                        Confirm      = $false
                        ErrorAction  = "Stop"
                    } 
                    $addSendAsPermission = Add-RecipientPermission @sendAsPermissionSplatParams

                    # Send auditlog to HelloID
                    $Log = @{
                        Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                        System            = "Exchange" # optional (free format text) 
                        Message           = "Successfully granted permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.userPrincipalName) ($($userToAdd.id))" # required (free format text) 
                        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = $mailbox.DisplayName # optional (free format text)
                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
                    }
                    Write-Information -Tags "Audit" -MessageData $log
                }
                catch {
                    $ex = $PSItem
                    if (-not [string]::IsNullOrEmpty($ex.Exception.Data.RemoteException.Message)) {
                        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Data.RemoteException.Message)"
                        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Data.RemoteException.Message)"
                    }
                    else {
                        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
                        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
                    }

                    $Log = @{
                        Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                        System            = "ExchangeOnline" # optional (free format text) 
                        Message           = $auditMessage # required (free format text) 
                        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = $mailboxDisplayName # optional (free format text) 
                        TargetIdentifier  = $mailboxPrimarySmtpAddress # optional (free format text) 
                    }
                    Write-Information -Tags "Audit" -MessageData $log
                    Write-Warning $warningMessage
                    Write-Error $auditMessage
                }
                break
            }

            "sendonbehalf" {
                # Grant Send on Behalf to shared mailbox
                try {
                    $actionMessage = "granting permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.userPrincipalName) ($($userToAdd.id))]"

                    $SendonBehalfPermissionSplatParams = @{
                        Identity            = $mailbox.Guid
                        GrantSendOnBehalfTo = @{ add = "$($userToAdd.id)" }
                        Confirm             = $false
                        ErrorAction         = "Stop"
                    }
                    Write-Warning ($SendonBehalfPermissionSplatParams | ConvertTo-Json -Depth 10)
                    $addSendonBehalfPermission = Set-Mailbox @SendonBehalfPermissionSplatParams

                    # Send auditlog to HelloID
                    $Log = @{
                        Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                        System            = "Exchange" # optional (free format text) 
                        Message           = "Successfully granted permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.userPrincipalName) ($($userToAdd.id))]" # required (free format text) 
                        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = $mailbox.DisplayName # optional (free format text)
                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
                    }
                    Write-Information -Tags "Audit" -MessageData $log
                }
                catch {
                    $ex = $PSItem
                    if (-not [string]::IsNullOrEmpty($ex.Exception.Data.RemoteException.Message)) {
                        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Data.RemoteException.Message)"
                        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Data.RemoteException.Message)"
                    }
                    else {
                        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
                        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
                    }

                    $Log = @{
                        Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                        System            = "ExchangeOnline" # optional (free format text) 
                        Message           = $auditMessage # required (free format text) 
                        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = $mailbox.DisplayName # optional (free format text)
                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
                    }
                    Write-Information -Tags "Audit" -MessageData $log
                    Write-Warning $warningMessage
                    Write-Error $auditMessage
                }
                break
            }
        }
    }

    # Revoke users permissions to shared mailbox
    $actionMessage = "revoking permission [$permission] from shared mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for users"
    foreach ($userToRemove in $usersToRemove) {
        switch ($permission) {
            "fullaccess" {
                # Revoke Full Access from shared mailbox
                try {
                    $actionMessage = "revoking permission [FullAccess] from mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.userPrincipalName) ($($userToRemove.id))]"

                    $FullAccessPermissionSplatParams = @{
                        Identity      = $mailbox.Guid
                        User          = $userToRemove.id
                        AccessRights  = "FullAccess"
                        ErrorAction   = "Stop"
                        Confirm       = $false
                        WarningAction = "SilentlyContinue"
                    } 
                    $removeFullAccessPermission = Remove-MailboxPermission @FullAccessPermissionSplatParams

                    # Send auditlog to HelloID
                    $Log = @{
                        Action            = "RevokeMembership" # optional. ENUM (undefined = default) 
                        System            = "Exchange" # optional (free format text) 
                        Message           = "Successfully revoked permission [FullAccess] from mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.userPrincipalName) ($($userToRemove.id))]" # required (free format text) 
                        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = $mailbox.DisplayName # optional (free format text)
                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
                    }
                    Write-Information -Tags "Audit" -MessageData $log
                }
                catch {
                    $ex = $PSItem
                    if (-not [string]::IsNullOrEmpty($ex.Exception.Data.RemoteException.Message)) {
                        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Data.RemoteException.Message)"
                        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Data.RemoteException.Message)"
                    }
                    else {
                        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
                        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
                    }

                    $Log = @{
                        Action            = "RevokeMembership" # optional. ENUM (undefined = default) 
                        System            = "ExchangeOnline" # optional (free format text) 
                        Message           = $auditMessage # required (free format text) 
                        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = $mailbox.DisplayName # optional (free format text)
                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
                    }
                    Write-Information -Tags "Audit" -MessageData $log
                    Write-Warning $warningMessage
                    Write-Error $auditMessage
                }
                break
            }
            
            "sendas" {
                # Revoke Send As from shared mailbox
                try {
                    $actionMessage = "revoking permission [Send As] from mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.userPrincipalName) ($($userToRemove.id))]"

                    $sendAsPermissionSplatParams = @{
                        Identity     = $mailbox.Guid
                        Trustee      = $userToRemove.id
                        AccessRights = "SendAs"
                        Confirm      = $false
                        ErrorAction  = "Stop"
                    } 
                    $removeSendAsPermission = Remove-RecipientPermission @sendAsPermissionSplatParams

                    # Send auditlog to HelloID
                    $Log = @{
                        Action            = "RevokeMembership" # optional. ENUM (undefined = default) 
                        System            = "Exchange" # optional (free format text) 
                        Message           = "Successfully revoked permission [Send As] from mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.id))]" # required (free format text) 
                        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = $mailbox.DisplayName # optional (free format text)
                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
                    }
                    Write-Information -Tags "Audit" -MessageData $log
                }
                catch {
                    $ex = $PSItem
                    if (-not [string]::IsNullOrEmpty($ex.Exception.Data.RemoteException.Message)) {
                        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Data.RemoteException.Message)"
                        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Data.RemoteException.Message)"
                    }
                    else {
                        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
                        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
                    }

                    $Log = @{
                        Action            = "RevokeMembership" # optional. ENUM (undefined = default) 
                        System            = "ExchangeOnline" # optional (free format text) 
                        Message           = $auditMessage # required (free format text) 
                        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = $mailbox.DisplayName # optional (free format text)
                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
                    }
                    Write-Information -Tags "Audit" -MessageData $log
                    Write-Warning $warningMessage
                    Write-Error $auditMessage
                }
                break
            }

            "sendonbehalf" {
                # Revoke Send on Behalf from shared mailbox
                try {
                    $actionMessage = "revoking permission [Send on Behalf] from mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.id))]"

                    $SendonBehalfPermissionSplatParams = @{
                        Identity            = $mailbox.Guid
                        GrantSendOnBehalfTo = @{ remove = "$($userToRemove.id)" }
                        Confirm             = $false
                        ErrorAction         = "Stop"
                    } 
                    $removeSendonBehalfPermission = Set-Mailbox @SendonBehalfPermissionSplatParams

                    # Send auditlog to HelloID
                    $Log = @{
                        Action            = "RevokeMembership" # optional. ENUM (undefined = default) 
                        System            = "Exchange" # optional (free format text) 
                        Message           = "Successfully revoked permission [Send on Behalf] from mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.id))]" # required (free format text) 
                        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = $mailbox.DisplayName # optional (free format text)
                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
                    }
                    Write-Information -Tags "Audit" -MessageData $log
                }
                catch {
                    $ex = $PSItem
                    if (-not [string]::IsNullOrEmpty($ex.Exception.Data.RemoteException.Message)) {
                        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Data.RemoteException.Message)"
                        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Data.RemoteException.Message)"
                    }
                    else {
                        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
                        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
                    }

                    $Log = @{
                        Action            = "RevokeMembership" # optional. ENUM (undefined = default) 
                        System            = "ExchangeOnline" # optional (free format text) 
                        Message           = $auditMessage # required (free format text) 
                        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = $mailbox.DisplayName # optional (free format text)
                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
                    }
                    Write-Information -Tags "Audit" -MessageData $log
                    Write-Warning $warningMessage
                    Write-Error $auditMessage
                }
                break
            }
        }
    }
}
catch {
    $ex = $PSItem
    if (-not [string]::IsNullOrEmpty($ex.Exception.Data.RemoteException.Message)) {
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Data.RemoteException.Message)"
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Data.RemoteException.Message)"
    }
    else {
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
    }

    $Log = @{
        # Action            = "" # optional. ENUM (undefined = default) 
        System            = "ExchangeOnline" # optional (free format text) 
        Message           = $auditMessage # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $mailbox.DisplayName # optional (free format text)
        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
    }
    
    Write-Information -Tags "Audit" -MessageData $log
    Write-Warning $warningMessage
    Write-Error $auditMessage
}
finally {
    # Docs: https://learn.microsoft.com/en-us/powershell/module/exchange/disconnect-exchangeonline?view=exchange-ps
    $deleteExchangeSessionSplatParams = @{
        Confirm     = $false
        ErrorAction = "Stop"
    }
    $null = Disconnect-ExchangeOnline @deleteExchangeSessionSplatParams
}
