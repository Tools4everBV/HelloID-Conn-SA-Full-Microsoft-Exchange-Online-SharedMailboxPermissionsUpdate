$identity = $form.gridMailbox.guid
$permission = $form.permission
$usersToAdd = $form.permissionList.leftToRight
$usersToRemove = $form.permissionList.rightToLeft

# Fixed values
$AutoMapping = $false

# PowerShell commands to import
$commands = @(
    "Get-Mailbox"
    , "Get-EXOMailbox"
    , "Set-Mailbox"
    , "Add-MailboxPermission"
    , "Add-RecipientPermission"
    , "Remove-MailboxPermission"
    , "Remove-RecipientPermission"
)

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

#region functions
function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }

        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            # $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message # Does not show the correct error message for the Raet IAM API calls
            $httpErrorObj.ErrorMessage = $ErrorObject.Exception.Message

        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [HelloID.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }

        Write-Output $httpErrorObj
    }
}

function Get-ErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $errorMessage = [PSCustomObject]@{
            VerboseErrorMessage = $null
            AuditErrorMessage   = $null
        }

        if ( $($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $httpErrorObject = Resolve-HTTPError -Error $ErrorObject

            $errorMessage.VerboseErrorMessage = $httpErrorObject.ErrorMessage

            $errorMessage.AuditErrorMessage = $httpErrorObject.ErrorMessage
        }

        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($errorMessage.VerboseErrorMessage)) {
            $errorMessage.VerboseErrorMessage = $ErrorObject.Exception.Message
        }
        if ([String]::IsNullOrEmpty($errorMessage.AuditErrorMessage)) {
            $errorMessage.AuditErrorMessage = $ErrorObject.Exception.Message
        }

        Write-Output $errorMessage
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
#endregion functions

#region Import module & connect
try {    
    $actionMessage = "importing module [ExchangeOnlineManagement]"
    $importModuleSplatParams = @{
        Name        = "ExchangeOnlineManagement"
        Cmdlet      = $commands
        Verbose     = $false
        ErrorAction = "Stop"
    }
    $null = Import-Module @importModuleSplatParams

    #region Retrieving certificate
    $actionMessage = "retrieving certificate"
    $certificate = Get-MSEntraCertificate
    #endregion Retrieving certificate
    
    #region Connect to Microsoft Exchange Online
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
    Write-Information "Connected to Microsoft Exchange Online"
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
    Write-Warning $warningMessage
    Write-Error $auditMessage
}

#region Get Mailbox
try {
    $properties = @(
        "Id"
        , "Guid"
        , "ExchangeGuid"
        , "DistinguishedName"
        , "Name"
        , "DisplayName"
        , "UserPrincipalName"
        , "EmailAddresses"
        , "RecipientTypeDetails"
        , "Alias"
    )

    $exchangeQuerySplatParams = @{
        Identity   = $identity
        ResultSize = "Unlimited"
    }

    Write-Information "Querying mailbox with identity [$identity]"
    $mailbox = Get-EXOMailbox @exchangeQuerySplatParams | Select-Object $properties
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying mailbox with identity [$identity]. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get Mailbox


#region Grant selected users permissions to shared mailbox
foreach ($userToAdd in $usersToAdd) {
    switch ($permission) {
        "fullaccess" {
            #region Grant Full Access to shared mailbox
            try {
                Write-Verbose "Granting permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))]"

                $FullAccessPermissionSplatParams = @{
                    Identity      = $mailbox.guid  # of $mailbox.UserPrincipalName
                    User          = $userToAdd.guid
                    AccessRights  = "FullAccess"
                    AutoMapping   = [bool]$AutoMapping
                    ErrorAction   = "Stop"
                    WarningAction = "SilentlyContinue"
                }

                $addFullAccessPermission = Add-MailboxPermission @FullAccessPermissionSplatParams

                Write-Information "Successfully granted permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))]"

                # Audit log for HelloID
                $Log = @{
                    Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                    System            = "Exchange" # optional (free format text) 
                    Message           = "Successfully granted permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))]" # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)
                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
                }
                #send result back
                Write-Information -Tags "Audit" -MessageData $log
            }
            catch {
                # Clean up error variables
                $verboseErrorMessage = $null
                $auditErrorMessage = $null

                $ex = $PSItem
                # If error message empty, fall back on $ex.Exception.Message
                if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
                    $verboseErrorMessage = $ex.Exception.Message
                }
                if ([String]::IsNullOrEmpty($auditErrorMessage)) {
                    $auditErrorMessage = $ex.Exception.Message
                }

                Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"

                # Audit log for HelloID
                $Log = @{
                    Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                    System            = "Exchange" # optional (free format text)
                    Message           = "Failed to grant permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))]. Error Message: $auditErrorMessage" # required (free format text) 
                    IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)
                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
                }
                #send result back
                Write-Information -Tags "Audit" -MessageData $log

                Write-Error "Error granting permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))]. Error Message: $auditErrorMessage"
            }
            #endregion Grant Full Access to shared mailbox
            break
        }
            
        "sendas" {
            #region Grant Send As to shared mailbox
            try {
                Write-Verbose "Granting permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))]"

                $sendAsPermissionSplatParams = @{
                    Identity     = $mailbox.Guid
                    Trustee      = $userToAdd.guid
                    AccessRights = "SendAs"
                    Confirm      = $false
                    ErrorAction  = "SilentlyContinue"
                } 

                $addSendAsPermission = Add-RecipientPermission @sendAsPermissionSplatParams

                Write-Information "Successfully granted permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))"

                # Audit log for HelloID
                $Log = @{
                    Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                    System            = "Exchange" # optional (free format text) 
                    Message           = "Successfully granted permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))" # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)
                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log
            }
            catch {
                # Clean up error variables
                $verboseErrorMessage = $null
                $auditErrorMessage = $null

                $ex = $PSItem
                # If error message empty, fall back on $ex.Exception.Message
                if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
                    $verboseErrorMessage = $ex.Exception.Message
                }
                if ([String]::IsNullOrEmpty($auditErrorMessage)) {
                    $auditErrorMessage = $ex.Exception.Message
                }

                Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"

                # Audit log for HelloID
                $Log = @{
                    Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                    System            = "Exchange" # optional (free format text)
                    Message           = "Failed to grant permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid)). Error Message: $auditErrorMessage" # required (free format text) 
                    IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)
                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log

                Write-Error "Failed to grant permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid)). Error Message: $auditErrorMessage"
            }
            #endregion Grant Send As to shared mailbox
            break
        }

        "sendonbehalf" {
            #region Grant Send on Behalf to shared mailbox
            try {
                Write-Verbose "Granting permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))]"

                $SendonBehalfPermissionSplatParams = @{
                    Identity            = $mailbox.Guid
                    GrantSendOnBehalfTo = @{ add = "$($userToAdd.guid)" }
                    Confirm             = $false
                    ErrorAction         = "SilentlyContinue"
                } 

                $addSendonBehalfPermission = Set-Mailbox @SendonBehalfPermissionSplatParams

                Write-Information "Successfully granted permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))]"

                # Audit log for HelloID
                $Log = @{
                    Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                    System            = "Exchange" # optional (free format text) 
                    Message           = "Successfully granted permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))]" # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)
                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
                }
                #send result back
                Write-Information -Tags "Audit" -MessageData $log
            }
            catch {
                # Clean up error variables
                $verboseErrorMessage = $null
                $auditErrorMessage = $null

                $ex = $PSItem
                # If error message empty, fall back on $ex.Exception.Message
                if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
                    $verboseErrorMessage = $ex.Exception.Message
                }
                if ([String]::IsNullOrEmpty($auditErrorMessage)) {
                    $auditErrorMessage = $ex.Exception.Message
                }

                Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"

                # Audit log for HelloID
                $Log = @{
                    Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                    System            = "Exchange" # optional (free format text)
                    Message           = "Failed to grant permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))]. Error Message: $auditErrorMessage" # required (free format text) 
                    IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)
                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
                }
                #send result back
                Write-Information -Tags "Audit" -MessageData $log

                Write-Error "Error granting permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.UserPrincipalName) ($($userToAdd.guid))]. Error Message: $auditErrorMessage"
            }
            #endregion Grant Send on Behalf to shared mailbox
            break
        }
    }
    #endregion Grant selected users permissions to shared mailbox
}


#region Revoke selected users permissions from shared mailbox
foreach ($userToRemove in $usersToRemove) {
    switch ($permission) {
        "fullaccess" {
            #region Revoke Full Access to shared mailbox
            try {
                Write-Verbose "Revoking permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))]"

                $FullAccessPermissionSplatParams = @{
                    Identity        = $mailbox.userprincipalname
                    User            = $userToRemove.userprincipalname
                    AccessRights    = "FullAccess"
                    ErrorAction   = "Stop"
                    Confirm      = $false
                    WarningAction = "SilentlyContinue"
                } 

                $removeFullAccessPermission = Remove-MailboxPermission @FullAccessPermissionSplatParams

                Write-Information "Successfully revoked permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))]"

                # Audit log for HelloID
                $Log = @{
                    Action            = "RevokeMembership" # optional. ENUM (undefined = default) 
                    System            = "Exchange" # optional (free format text) 
                    Message           = "Successfully revoked permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))]" # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)
                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
                }
                #send result back
                Write-Information -Tags "Audit" -MessageData $log
            }
            catch {
                # Clean up error variables
                $verboseErrorMessage = $null
                $auditErrorMessage = $null

                $ex = $PSItem
                # If error message empty, fall back on $ex.Exception.Message
                if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
                    $verboseErrorMessage = $ex.Exception.Message
                }
                if ([String]::IsNullOrEmpty($auditErrorMessage)) {
                    $auditErrorMessage = $ex.Exception.Message
                }

                Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"

                # Audit log for HelloID
                $Log = @{
                    Action            = "RevokeMembership" # optional. ENUM (undefined = default) 
                    System            = "Exchange" # optional (free format text)
                    Message           = "Failed to revoke permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))]. Error Message: $auditErrorMessage" # required (free format text) 
                    IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)
                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
                }
                #send result back
                Write-Information -Tags "Audit" -MessageData $log

                Write-Error "Error revoking permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))]. Error Message: $auditErrorMessage"
            }
            #endregion Revoke Full Access to shared mailbox
            break
        }
            
        "sendas" {
            #region Revoke Send As to shared mailbox
            try {
                Write-Verbose "Revoking permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))]"

                $sendAsPermissionSplatParams = @{
                    Identity     = $mailbox.Guid
                    Trustee      = $userToRemove.guid
                    AccessRights = "SendAs"
                    Confirm      = $false
                    ErrorAction  = "SilentlyContinue"
                } 

                $removeSendAsPermission = Remove-RecipientPermission @sendAsPermissionSplatParams

                Write-Information "Successfully revoked permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))"

                # Audit log for HelloID
                $Log = @{
                    Action            = "RevokeMembership" # optional. ENUM (undefined = default) 
                    System            = "Exchange" # optional (free format text) 
                    Message           = "Successfully revoked permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))" # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)
                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log
            }
            catch {
                # Clean up error variables
                $verboseErrorMessage = $null
                $auditErrorMessage = $null

                $ex = $PSItem
                # If error message empty, fall back on $ex.Exception.Message
                if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
                    $verboseErrorMessage = $ex.Exception.Message
                }
                if ([String]::IsNullOrEmpty($auditErrorMessage)) {
                    $auditErrorMessage = $ex.Exception.Message
                }

                Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"

                # Audit log for HelloID
                $Log = @{
                    Action            = "RevokeMembership" # optional. ENUM (undefined = default) 
                    System            = "Exchange" # optional (free format text)
                    Message           = "Failed to revoke permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid)). Error Message: $auditErrorMessage" # required (free format text) 
                    IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)
                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log

                Write-Error "Failed to revoke permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid)). Error Message: $auditErrorMessage"
            }
            #endregion Revoke Send As to shared mailbox
            break
        }

        "sendonbehalf" {
            #region Revoke Send on Behalf to shared mailbox
            try {
                Write-Verbose "Revoking permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))]"

                $SendonBehalfPermissionSplatParams = @{
                    Identity            = $mailbox.Guid
                    GrantSendOnBehalfTo = @{ remove = "$($userToRemove.guid)" }
                    Confirm             = $false
                    ErrorAction         = "SilentlyContinue"
                } 

                $removeSendonBehalfPermission = Set-Mailbox @SendonBehalfPermissionSplatParams

                Write-Information "Successfully revoked permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))]"

                # Audit log for HelloID
                $Log = @{
                    Action            = "RevokeMembership" # optional. ENUM (undefined = default) 
                    System            = "Exchange" # optional (free format text) 
                    Message           = "Successfully revoked permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))]" # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)
                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
                }
                #send result back
                Write-Information -Tags "Audit" -MessageData $log
            }
            catch {
                # Clean up error variables
                $verboseErrorMessage = $null
                $auditErrorMessage = $null

                $ex = $PSItem
                # If error message empty, fall back on $ex.Exception.Message
                if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
                    $verboseErrorMessage = $ex.Exception.Message
                }
                if ([String]::IsNullOrEmpty($auditErrorMessage)) {
                    $auditErrorMessage = $ex.Exception.Message
                }

                Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"

                # Audit log for HelloID
                $Log = @{
                    Action            = "RevokeMembership" # optional. ENUM (undefined = default) 
                    System            = "Exchange" # optional (free format text)
                    Message           = "Failed to revoke permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))]. Error Message: $auditErrorMessage" # required (free format text) 
                    IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = $mailbox.DisplayName # optional (free format text)
                    TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)
                }
                #send result back
                Write-Information -Tags "Audit" -MessageData $log

                Write-Error "Error revoking permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.guid))]. Error Message: $auditErrorMessage"
            }
            #endregion Revoke Send on Behalf to shared mailbox
            break
        }
    }
    #endregion Revoke selected users permissions to shared mailbox
}
#>

#Remove Exchange session
# Docs: https://learn.microsoft.com/en-us/powershell/module/exchange/disconnect-exchangeonline?view=exchange-ps
$deleteExchangeSessionSplatParams = @{
    Confirm     = $false
    ErrorAction = "Stop"
}
$null = Disconnect-ExchangeOnline @deleteExchangeSessionSplatParams
Write-Information "Disconnected from Microsoft Exchange Online"

