# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("mailbox Management","Exchange Online") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> EntraIdCertificateBase64String
$tmpName = @'
EntraIdCertificateBase64String
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "True"});

#Global variable #2 >> EntraIDAppId
$tmpName = @'
EntraIDAppId
'@ 
$tmpValue = @'
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #3 >> EntraIdCertificatePassword
$tmpName = @'
EntraIdCertificatePassword
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "True"});

#Global variable #4 >> EntraIdOrganization
$tmpName = @'
EntraIdOrganization
'@ 
$tmpValue = @'
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #5 >> EntraIDtenantID
$tmpName = @'
EntraIDtenantID
'@ 
$tmpValue = @'
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});


#make sure write-information logging is visual
$InformationPreference = "continue"

# Check for prefilled API Authorization header
if (-not [string]::IsNullOrEmpty($portalApiBasic)) {
    $script:headers = @{"authorization" = $portalApiBasic}
    Write-Information "Using prefilled API credentials"
} else {
    # Create authorization headers with HelloID API key
    $pair = "$apiKey" + ":" + "$apiSecret"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $key = "Basic $base64"
    $script:headers = @{"authorization" = $Key}
    Write-Information "Using manual API credentials"
}

# Check for prefilled PortalBaseURL
if (-not [string]::IsNullOrEmpty($portalBaseUrl)) {
    $script:PortalBaseUrl = $portalBaseUrl
    Write-Information "Using prefilled PortalURL: $script:PortalBaseUrl"
} else {
    $script:PortalBaseUrl = $portalUrl
    Write-Information "Using manual PortalURL: $script:PortalBaseUrl"
}

# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"  

# Make sure to reveive an empty array using PowerShell Core
function ConvertFrom-Json-WithEmptyArray([string]$jsonString) {
    # Running in PowerShell Core?
    if($IsCoreCLR -eq $true){
        $r = [Object[]]($jsonString | ConvertFrom-Json -NoEnumerate)
        return ,$r  # Force return value to be an array using a comma
    } else {
        $r = [Object[]]($jsonString | ConvertFrom-Json)
        return ,$r  # Force return value to be an array using a comma
    }
}

function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )

    $Name = $Name + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl + "api/v1/automation/variables/named/$Name")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false

        if ([string]::IsNullOrEmpty($response.automationVariableGuid)) {
            #Create Variable
            $body = @{
                name     = $Name;
                value    = $Value;
                secret   = $Secret;
                ItemType = 0;
            }    
            $body = ConvertTo-Json -InputObject $body -Depth 100

            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid

            Write-Information "Variable '$Name' created$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-Warning "Variable '$Name' already exists$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        }
    } catch {
        Write-Error "Variable '$Name', message: $_"
    }
}

function Invoke-HelloIDAutomationTask {
    param(
        [parameter(Mandatory)][String]$TaskName,
        [parameter(Mandatory)][String]$UseTemplate,
        [parameter(Mandatory)][String]$AutomationContainer,
        [parameter(Mandatory)][String][AllowEmptyString()]$Variables,
        [parameter(Mandatory)][String]$PowershellScript,
        [parameter()][String][AllowEmptyString()]$ObjectGuid,
        [parameter()][String][AllowEmptyString()]$ForceCreateTask,
        [parameter(Mandatory)][Ref]$returnObject
    )

    $TaskName = $TaskName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl +"api/v1/automationtasks?search=$TaskName&container=$AutomationContainer")
        $responseRaw = (Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false) 
        $response = $responseRaw | Where-Object -filter {$_.name -eq $TaskName}

        if([string]::IsNullOrEmpty($response.automationTaskGuid) -or $ForceCreateTask -eq $true) {
            #Create Task

            $body = @{
                name                = $TaskName;
                useTemplate         = $UseTemplate;
                powerShellScript    = $PowershellScript;
                automationContainer = $AutomationContainer;
                objectGuid          = $ObjectGuid;
                variables           = (ConvertFrom-Json-WithEmptyArray($Variables));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100

            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid

            Write-Information "Powershell task '$TaskName' created$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-Warning "Powershell task '$TaskName' already exists$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        }
    } catch {
        Write-Error "Powershell task '$TaskName', message: $_"
    }

    $returnObject.Value = $taskGuid
}

function Invoke-HelloIDDatasource {
    param(
        [parameter(Mandatory)][String]$DatasourceName,
        [parameter(Mandatory)][String]$DatasourceType,
        [parameter(Mandatory)][String][AllowEmptyString()]$DatasourceModel,
        [parameter()][String][AllowEmptyString()]$DatasourceStaticValue,
        [parameter()][String][AllowEmptyString()]$DatasourcePsScript,        
        [parameter()][String][AllowEmptyString()]$DatasourceInput,
        [parameter()][String][AllowEmptyString()]$AutomationTaskGuid,
        [parameter()][String][AllowEmptyString()]$DatasourceRunInCloud,
        [parameter(Mandatory)][Ref]$returnObject
    )

    $DatasourceName = $DatasourceName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    $datasourceTypeName = switch($DatasourceType) { 
        "1" { "Native data source"; break} 
        "2" { "Static data source"; break} 
        "3" { "Task data source"; break} 
        "4" { "Powershell data source"; break}
    }

    try {
        $uri = ($script:PortalBaseUrl +"api/v1/datasource/named/$DatasourceName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
    
        if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
            #Create DataSource
            $body = @{
                name               = $DatasourceName;
                type               = $DatasourceType;
                model              = (ConvertFrom-Json-WithEmptyArray($DatasourceModel));
                automationTaskGUID = $AutomationTaskGuid;
                value              = (ConvertFrom-Json-WithEmptyArray($DatasourceStaticValue));
                script             = $DatasourcePsScript;
                input              = (ConvertFrom-Json-WithEmptyArray($DatasourceInput));
                runInCloud         = $DatasourceRunInCloud;
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            
            $datasourceGuid = $response.dataSourceGUID
            Write-Information "$datasourceTypeName '$DatasourceName' created$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-Warning "$datasourceTypeName '$DatasourceName' already exists$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        }
    } catch {
        Write-Error "$datasourceTypeName '$DatasourceName', message: $_"
    }

    $returnObject.Value = $datasourceGuid
}

function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )

    $FormName = $FormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/forms/$FormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }

        if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true)) {
            #Create Dynamic form
            $body = @{
                Name       = $FormName;
                FormSchema = (ConvertFrom-Json-WithEmptyArray($FormSchema));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100

            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body

            $formGuid = $response.dynamicFormGUID
            Write-Information "Dynamic form '$formName' created$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-Warning "Dynamic form '$FormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        }
    } catch {
        Write-Error "Dynamic form '$FormName', message: $_"
    }

    $returnObject.Value = $formGuid
}


function Invoke-HelloIDDelegatedForm {
    param(
        [parameter(Mandatory)][String]$DelegatedFormName,
        [parameter(Mandatory)][String]$DynamicFormGuid,
        [parameter()][Array][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter()][String][AllowEmptyString()]$task,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    $DelegatedFormName = $DelegatedFormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$DelegatedFormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }

        if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
            #Create DelegatedForm
            $body = @{
                name            = $DelegatedFormName;
                dynamicFormGUID = $DynamicFormGuid;
                isEnabled       = "True";
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
                task            = ConvertFrom-Json -inputObject $task;
            }
            if(-not[String]::IsNullOrEmpty($AccessGroups)) { 
                $body += @{
                    accessGroups    = (ConvertFrom-Json-WithEmptyArray($AccessGroups));
                }
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100

            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body

            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Information "Delegated form '$DelegatedFormName' created$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
            $delegatedFormCreated = $true

            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-Information "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Warning "Delegated form '$DelegatedFormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
        }
    } catch {
        Write-Error "Delegated form '$DelegatedFormName', message: $_"
    }

    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}

<# Begin: HelloID Global Variables #>
foreach ($item in $globalHelloIDVariables) {
	Invoke-HelloIDGlobalVariable -Name $item.name -Value $item.value -Secret $item.secret 
}
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "exchange-online-shared-mailbox-manage-permissions | EXO-Get-Mailbox-Permissions-EntraID-Get-Users" #>
$tmpPsScript = @'
# Variables configured in form
$identity = $datasource.selectedmailbox.guid
$permission = $datasource.Permission

# Global variables
# Outcommented as these are set from Global Variables
# $EntraIdOrganization = ""
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# Fixed values
# Properties to select - Select only needed properties to limit memory usage and speed up processing
$propertiesToSelect = @(
    "id",
    "userPrincipalName",
    "displayName",
    "mail"
)

# PowerShell commands to import
$commands = @(
    "Get-Mailbox"
    , "Get-EXOMailbox"
    , "Get-RecipientPermission"
    , "Get-MailboxPermission"
    , "Get-User"
)

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $Certificate,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $AppId,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $TenantId
    )
    try {
        # Get the DER encoded bytes of the certificate
        $derBytes = $Certificate.RawData

        # Compute the SHA-256 hash of the DER encoded bytes
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Create a JWT (JSON Web Token) header
        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        # Calculate the Unix timestamp (seconds since 1970-01-01T00:00:00Z) for 'exp', 'nbf' and 'iat'
        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        # Create a JWT payload
        $payload = [Ordered]@{
            'iss' = "$($AppId)"
            'sub' = "$($AppId)"
            'aud' = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600) # Expires in 1 hour
            'nbf' = ($currentUnixTimestamp - 300) # Not before 5 minutes ago
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Extract the private key from the certificate
        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        # Sign the JWT
        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Ensure the certificate has a private key
        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        # Create the JWT token
        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $AppId
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

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

# Exchange Online Management module actions
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

    if ($permission.ToLower() -eq "fullaccess") {
        $actionMessage = "querying FullAccess permissions for mailbox [$($identity)]"
        # Docs: https://learn.microsoft.com/en-us/powershell/module/exchange/get-mailboxpermission?view=exchange-ps
        $currentPermissions = Get-MailboxPermission -Identity $identity # Returns UPN

        $currentPermissions = $currentPermissions | Where-Object { ($_.accessRights -like "*fullaccess*") -and -not($_.Deny -eq $true) -and -not($_.User -match "NT AUTHORITY") -and -not($_.User -like "*\Domain Admins") }
        $currentPermissionsUsers = $currentPermissions.User    

        $currentPermissionsUsers = $currentPermissions | ForEach-Object { $_.User.ToString() }

    }
    elseif ($permission.ToLower() -eq "sendas") {
        $actionMessage = "querying SendAs permissions for mailbox [$($identity)]"
        # Docs: https://learn.microsoft.com/en-us/powershell/module/exchange/get-recipientpermission?view=exchange-ps
        $currentPermissions = Get-RecipientPermission -Identity $identity -AccessRights 'SendAs' # Returns UPN

        $currentPermissions = $currentPermissions | Where-Object { -not($_.Deny -eq $true) -and -not($_.Trustee -match "NT AUTHORITY") -and -not($_.Trustee -like "*\Domain Admins") }
        $currentPermissionsUsers = $currentPermissions.Trustee
    }
    elseif ($permission.ToLower() -eq "sendonbehalf") {
        $actionMessage = "querying SendOnBehalf permissions for mailbox [$($identity)]"
        # Docs: https://learn.microsoft.com/en-us/powershell/module/exchange/get-exomailbox?view=exchange-ps
        $exchangeMailbox = Get-EXOMailbox -Identity $identity -Properties GrantSendOnBehalfTo

        $currentPermissions = $exchangeMailbox.GrantSendOnBehalfTo # Returns id only
        $currentPermissionsUsers = $currentPermissions
    }
    else {
        throw "Could not match right '$($permission)' to FullAccess, SendAs or SendOnBehalf"
    }
    Write-Information "Queried [$permission] permissions for mailbox [$($identity)]. Result count: $(@($currentPermissionsUsers).Count)"
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
    # exit # use when using multiple try/catch and the script must stop
}
finally {
    # Docs: https://learn.microsoft.com/en-us/powershell/module/exchange/disconnect-exchangeonline?view=exchange-ps
    $deleteExchangeSessionSplatParams = @{
        Confirm     = $false
        ErrorAction = "Stop"
        Verbose     = $false
    }
    $null = Disconnect-ExchangeOnline @deleteExchangeSessionSplatParams
}

# Graph API actions
try {
    # Create access token
    $actionMessage = "creating access token"
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate -AppId $EntraIdAppId -TenantId $EntraIdTenantId

    # Create headers
    $actionMessage = "creating headers"
    $headers = @{
        "Authorization"    = "Bearer $($entraToken)"
        "Accept"           = "application/json"
        "Content-Type"     = "application/json"
        "ConsistencyLevel" = "eventual" # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
    }

    # Get Microsoft Entra ID Users
    # Docs: https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0&tabs=http
    $actionMessage = "querying user information from Microsoft Entra ID for users"
    $microsoftEntraIDUsers = [System.Collections.ArrayList]@()
    foreach ($currentPermissionsUser in $currentPermissionsUsers) {
        if ($permission.ToLower() -eq "fullaccess" -or $permission.ToLower() -eq "sendas") {
            # For FullAccess and SendAs permissions, the user is returned as UPN. We can filter on userPrincipalName.
            $filter = "`$filter=userPrincipalName eq '$($currentPermissionsUser)'"
        }
        elseif ($permission.ToLower() -eq "sendonbehalf") {
            # For SendOnBehalf permissions, the user is returned as id only. We can filter on id.
            $filter = "`$filter=id eq '$($currentPermissionsUser)'"
        }

        $getMicrosoftEntraIDUserSplatParams = @{
            Uri         = "https://graph.microsoft.com/v1.0/users?$filter&`$select=$($propertiesToSelect -join ',')&`$top=999&`$count=true"
            Headers     = $headers
            Method      = "GET"
            Verbose     = $false
            ErrorAction = "Stop"
        }
        
        $getMicrosoftEntraIDUserResponse = $null
        $getMicrosoftEntraIDUserResponse = Invoke-RestMethod @getMicrosoftEntraIDUserSplatParams

        if ($getMicrosoftEntraIDUserResponse.Value) {
            # Select only specified properties to limit memory usage
            $microsoftEntraIDUser = $null
            $microsoftEntraIDUser = $getMicrosoftEntraIDUserResponse.Value | Select-Object $propertiesToSelect
            [void]$microsoftEntraIDUsers.Add($microsoftEntraIDUser)
        }
        else {
            # Write-Warning "No user found in Microsoft Entra ID matching filter: $filter"
        }
    }
    Write-Information "Queried user information from Microsoft Entra ID for users. Result count: $(@($microsoftEntraIDUsers).Count)"

    # Send results to HelloID
    $actionMessage = "sending results to HelloID"
    $microsoftEntraIDUsers | Add-Member -MemberType NoteProperty -Name "displayValue" -Value $null -Force
    $microsoftEntraIDUsers | Sort-Object -Property displayName | ForEach-Object {
        # Set displayValue property with format: Display Name [UserPrincipalName]
        $_.displayValue = "$($_.displayName) ($($_.userPrincipalName))"

        Write-Output $_
    }
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    Write-Warning $warningMessage
    Write-Error $auditMessage
}
'@ 
$tmpModel = @'
[{"key":"id","type":0},{"key":"userPrincipalName","type":0},{"key":"displayName","type":0},{"key":"mail","type":0},{"key":"displayValue","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"selectedMailbox","type":0,"options":1},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"Permission","type":0,"options":1}]
'@ 
$dataSourceGuid_2 = [PSCustomObject]@{} 
$dataSourceGuid_2_Name = @'
exchange-online-shared-mailbox-manage-permissions | EXO-Get-Mailbox-Permissions-EntraID-Get-Users
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_2_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "False" -returnObject ([Ref]$dataSourceGuid_2) 
<# End: DataSource "exchange-online-shared-mailbox-manage-permissions | EXO-Get-Mailbox-Permissions-EntraID-Get-Users" #>

<# Begin: DataSource "exchange-online-shared-mailbox-manage-permissions | EXO-Get-Shared-Mailboxes-Wildcard-Name-EmailAddresses" #>
$tmpPsScript = @'
# Variables configured in form
$searchValue = $datasource.searchValue
if ($searchValue -eq "*") {
    $filter = "RecipientTypeDetails -eq 'SharedMailbox'"
}
else {
    $filter = "(Name -like '*$searchValue*' -or EmailAddresses -like '*$searchValue*') -and RecipientTypeDetails -eq 'SharedMailbox'"
}

# Global variables
# Outcommented as these are set from Global Variables
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# Fixed values
# Properties to select - Select only needed properties to limit memory usage and speed up processing
$propertiesToSelect = @(
    "Id"
    , "Guid"
    , "ExchangeGuid"
    , "DisplayName"
    , "PrimarySmtpAddress"
    , "EmailAddresses"
    , "Alias"
    , "RecipientTypeDetails"
)

# PowerShell commands to import
# Use Get-EXORecipient instead of Get-Mailbox as Get-EXORecipient is faster
$commands = @(
    "Get-Recipient"
    , "Get-EXORecipient"
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

    # Convert base64 certificate string to certificate object
    $actionMessage = "converting base64 certificate string to certificate object"

    $certificate = Get-MSEntraCertificate -CertificateBase64String $EntraIdCertificateBase64String -CertificatePassword $EntraIdCertificatePassword

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

    # Get Mailboxes
    # Docs: https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-exorecipient?view=exchange-ps
    $actionMessage = "querying shared mailboxes that match filter [$($filter)]"

    $getMailboxesSplatParams = @{
        RecipientTypeDetails = "SharedMailbox"
        ResultSize           = "Unlimited"
        Filter               = $filter
        Properties           = $propertiesToSelect
        ErrorAction          = 'Stop'
    }

    $mailboxes = Get-EXORecipient @getMailboxesSplatParams | Select-Object -Property $propertiesToSelect
    Write-Information "Queried shared mailboxes that match filter [$($filter)]. Result count: $(($mailboxes | Measure-Object).Count)"

    # Sort and Send results to HelloID
    $actionMessage = "sending results to HelloID"
    $mailboxes | Sort-Object -Property DisplayName | ForEach-Object {
        Write-Output $_
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
    Write-Warning $warningMessage
    Write-Error $auditMessage
    # exit # use when using multiple try/catch and the script must stop
}
finally {
    # Docs: https://learn.microsoft.com/en-us/powershell/module/exchange/disconnect-exchangeonline?view=exchange-ps
    $deleteExchangeSessionSplatParams = @{
        Confirm     = $false
        ErrorAction = "Stop"
    }
    $null = Disconnect-ExchangeOnline @deleteExchangeSessionSplatParams
}
'@ 
$tmpModel = @'
[{"key":"Id","type":0},{"key":"Guid","type":0},{"key":"ExchangeGuid","type":0},{"key":"DisplayName","type":0},{"key":"PrimarySmtpAddress","type":0},{"key":"EmailAddresses","type":0},{"key":"Alias","type":0},{"key":"RecipientTypeDetails","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"searchValue","type":0,"options":1}]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
exchange-online-shared-mailbox-manage-permissions | EXO-Get-Shared-Mailboxes-Wildcard-Name-EmailAddresses
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "False" -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "exchange-online-shared-mailbox-manage-permissions | EXO-Get-Shared-Mailboxes-Wildcard-Name-EmailAddresses" #>

<# Begin: DataSource "exchange-online-shared-mailbox-manage-permissions | EntraID-Get-All-Users" #>
$tmpPsScript = @'
$filter = "`$filter=userType eq 'Member'" # Get all users, excluding guest users

# Global variables
# Outcommented as these are set from Global Variables
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# Fixed values
# Properties to select - Select only needed properties to limit memory usage and speed up processing
$propertiesToSelect = @(
    "id",
    "userPrincipalName",
    "displayName",
    "mail"
)

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $Certificate,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $AppId,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $TenantId
    )
    try {
        # Get the DER encoded bytes of the certificate
        $derBytes = $Certificate.RawData

        # Compute the SHA-256 hash of the DER encoded bytes
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Create a JWT (JSON Web Token) header
        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        # Calculate the Unix timestamp (seconds since 1970-01-01T00:00:00Z) for 'exp', 'nbf' and 'iat'
        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        # Create a JWT payload
        $payload = [Ordered]@{
            'iss' = "$($AppId)"
            'sub' = "$($AppId)"
            'aud' = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600) # Expires in 1 hour
            'nbf' = ($currentUnixTimestamp - 300) # Not before 5 minutes ago
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Extract the private key from the certificate
        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        # Sign the JWT
        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Ensure the certificate has a private key
        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        # Create the JWT token
        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $AppId
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

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
    # Convert base64 certificate string to certificate object
    $actionMessage = "converting base64 certificate string to certificate object"
    $certificate = Get-MSEntraCertificate -CertificateBase64String $EntraIdCertificateBase64String -CertificatePassword $EntraIdCertificatePassword

    # Create access token
    $actionMessage = "creating access token"
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate -AppId $EntraIdAppId -TenantId $EntraIdTenantId

    # Create headers
    $actionMessage = "creating headers"
    $headers = @{
        "Authorization"    = "Bearer $($entraToken)"
        "Accept"           = "application/json"
        "Content-Type"     = "application/json"
        "ConsistencyLevel" = "eventual" # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
    }

    # Get Microsoft Entra ID Users
    # API docs: https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0&tabs=http
    $actionMessage = "querying Microsoft Entra ID Users matching filter [$filter]"
    $microsoftEntraIDUsers = [System.Collections.ArrayList]@()
    do {
        $getMicrosoftEntraIDUsersSplatParams = @{
            Uri         = "https://graph.microsoft.com/v1.0/users?$filter&`$select=$($propertiesToSelect -join ',')&`$top=999&`$count=true"
            Headers     = $headers
            Method      = "GET"
            Verbose     = $false
            ErrorAction = "Stop"
        }
        if (-not[string]::IsNullOrEmpty($getMicrosoftEntraIDUsersResponse.'@odata.nextLink')) {
            $getMicrosoftEntraIDUsersSplatParams["Uri"] = $getMicrosoftEntraIDUsersResponse.'@odata.nextLink'
        }
        
        $getMicrosoftEntraIDUsersResponse = $null
        $getMicrosoftEntraIDUsersResponse = Invoke-RestMethod @getMicrosoftEntraIDUsersSplatParams
    
        # Select only specified properties to limit memory usage
        $getMicrosoftEntraIDUsersResponse.Value = $getMicrosoftEntraIDUsersResponse.Value | Select-Object $propertiesToSelect

        if ($getMicrosoftEntraIDUsersResponse.Value -is [array]) {
            [void]$microsoftEntraIDUsers.AddRange($getMicrosoftEntraIDUsersResponse.Value)
        }
        else {
            [void]$microsoftEntraIDUsers.Add($getMicrosoftEntraIDUsersResponse.Value)
        }
    } while (-not[string]::IsNullOrEmpty($getMicrosoftEntraIDUsersResponse.'@odata.nextLink'))
    Write-Information "Queried Microsoft Entra ID Users matching filter [$filter]. Result count: $(@($microsoftEntraIDUsers).Count)"

    # Send results to HelloID
    $actionMessage = "sending results to HelloID"
    $microsoftEntraIDUsers | Add-Member -MemberType NoteProperty -Name "displayValue" -Value $null -Force
    $microsoftEntraIDUsers | Sort-Object -Property displayName | ForEach-Object {
        # Set displayValue property with format: Display Name [UserPrincipalName]
        $_.displayValue = "$($_.displayName) ($($_.userPrincipalName))"

        Write-Output $_
    }
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    Write-Warning $warningMessage
    Write-Error $auditMessage
}
  
'@ 
$tmpModel = @'
[{"key":"id","type":0},{"key":"userPrincipalName","type":0},{"key":"displayName","type":0},{"key":"mail","type":0},{"key":"displayValue","type":0}]
'@ 
$tmpInput = @'
[]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
exchange-online-shared-mailbox-manage-permissions | EntraID-Get-All-Users
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "False" -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "exchange-online-shared-mailbox-manage-permissions | EntraID-Get-All-Users" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "Exchange online - Shared mailbox - Manage permissions" #>
$tmpSchema = @"
[{"label":"Select mailbox","fields":[{"templateOptions":{"title":"Retrieving this information from Exchange takes an average of +/- 10 seconds. Please wait while the data is loaded.","titleField":"","bannerType":"Info","useBody":false},"type":"textbanner","summaryVisibility":"Hide element","body":"Text Banner Content","requiresTemplateOptions":false,"requiresKey":false,"requiresDataSource":false},{"key":"searchMailbox","templateOptions":{"label":"Search (wildcard search in Name and Email addresses)","placeholder":"Name or Email addresses (use * to search all shared mailboxes)","required":true},"type":"input","summaryVisibility":"Hide element","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"gridMailbox","templateOptions":{"label":"Mailbox","required":true,"grid":{"columns":[{"headerName":"Display Name","field":"DisplayName"},{"headerName":"Primary Smtp Address","field":"PrimarySmtpAddress"},{"headerName":"Email Addresses","field":"EmailAddresses"},{"headerName":"Alias","field":"Alias"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[{"propertyName":"searchValue","otherFieldValue":{"otherFieldKey":"searchMailbox"}}]}},"useDefault":false,"allowCsvDownload":true},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true}]},{"label":"Mailbox Permissions","fields":[{"templateOptions":{"title":"Retrieving this information from Exchange takes an average of +/- 30 seconds. Please wait while the data is loaded.","titleField":"","bannerType":"Info","useBody":false},"type":"textbanner","summaryVisibility":"Hide element","body":"Text Banner Content","requiresTemplateOptions":false,"requiresKey":false,"requiresDataSource":false},{"key":"permission","templateOptions":{"label":"Permission","required":false,"useObjects":true,"useDataSource":false,"useFilter":false,"options":[{"value":"fullaccess","text":"Full Access"},{"value":"sendas","text":"Send As"},{"value":"sendonbehalf","text":"Send on Behalf"}]},"type":"dropdown","summaryVisibility":"Show","textOrLabel":"text","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"permissionList","templateOptions":{"label":"Mailbox permissions","required":false,"filterable":true,"useDataSource":true,"dualList":{"options":[{"guid":"75ea2890-88f8-4851-b202-626123054e14","Name":"Apple"},{"guid":"0607270d-83e2-4574-9894-0b70011b663f","Name":"Pear"},{"guid":"1ef6fe01-3095-4614-a6db-7c8cd416ae3b","Name":"Orange"}],"optionKeyProperty":"id","optionDisplayProperty":"displayValue"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[]}},"destinationDataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_2","input":{"propertyInputs":[{"propertyName":"selectedMailbox","otherFieldValue":{"otherFieldKey":"gridMailbox"}},{"propertyName":"Permission","otherFieldValue":{"otherFieldKey":"permission"}}]}}},"hideExpression":"!model[\"permission\"]","type":"duallist","summaryVisibility":"Show","sourceDataSourceIdentifierSuffix":"source-datasource","destinationDataSourceIdentifierSuffix":"destination-datasource","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
Exchange online - Shared mailbox - Manage permissions
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
if(-not[String]::IsNullOrEmpty($delegatedFormAccessGroupNames)){
    foreach($group in $delegatedFormAccessGroupNames) {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
            $delegatedFormAccessGroupGuid = $response.groupGuid
            $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
        
            Write-Information "HelloID (access)group '$group' successfully found$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormAccessGroupGuid })"
        } catch {
            Write-Error "HelloID (access)group '$group', message: $_"
        }
    }
    if($null -ne $delegatedFormAccessGroupGuids){
        $delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Depth 100 -Compress)
    }
}

$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $response = $response | Where-Object {$_.name.en -eq $category}
    
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
    
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body -Depth 100

        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid

        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Depth 100 -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
Exchange online - Shared Mailbox - Manage permissions
'@
$tmpTask = @'
{"name":"- WIP - Exchange online - Shared Mailbox - Manage permissions","script":"# variables configured in form\r\n$mailbox = $form.gridMailbox\r\n$permission = $form.permission\r\n$usersToAdd = $form.permissionList.leftToRight\r\n$usersToRemove = $form.permissionList.rightToLeft\r\n\r\n# Global variables\r\n# Outcommented as these are set from Global Variables\r\n# $EntraIdOrganization = \"\"\r\n# $EntraIdAppId = \"\"\r\n# $EntraIdCertificateBase64String = \"\"\r\n# $EntraIdCertificatePassword = \"\"\r\n\r\n# Fixed values\r\n$commands = @(\r\n    \"Add-MailboxPermission\",\r\n    \"Add-RecipientPermission\",\r\n    \"Set-Mailbox\",\r\n    \"Remove-MailboxPermission\",\r\n    \"Remove-RecipientPermission\"\r\n)\r\n\r\n# Enable TLS1.2\r\n[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12\r\n\r\n# Set debug logging\r\n$VerbosePreference = \"SilentlyContinue\"\r\n$InformationPreference = \"Continue\"\r\n$WarningPreference = \"Continue\"\r\n\r\n#region functions\r\nfunction Get-MSEntraCertificate {\r\n    [CmdletBinding()]\r\n    param(\r\n        [Parameter(Mandatory)]\r\n        [ValidateNotNullOrEmpty()]\r\n        [string]\r\n        $CertificateBase64String,\r\n        \r\n        [Parameter(Mandatory)]\r\n        [ValidateNotNullOrEmpty()]\r\n        [string]\r\n        $CertificatePassword\r\n    )\r\n    try {\r\n        $rawCertificate = [system.convert]::FromBase64String($CertificateBase64String)\r\n        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)\r\n        Write-Output $certificate\r\n    }\r\n    catch {\r\n        $PSCmdlet.ThrowTerminatingError($_)\r\n    }\r\n}\r\n#endregion functions\r\n\r\ntry {\r\n    # Import module\r\n    $actionMessage = \"importing module [ExchangeOnlineManagement]\"\r\n        \r\n    $importModuleSplatParams = @{\r\n        Name        = \"ExchangeOnlineManagement\"\r\n        Cmdlet      = $commands\r\n        Verbose     = $false\r\n        ErrorAction = \"Stop\"\r\n    }\r\n\r\n    $null = Import-Module @importModuleSplatParams\r\n\r\n    Write-Verbose \"Imported module [ExchangeOnlineManagement]\"\r\n\r\n    # Convert base64 certificate string to certificate object\r\n    $actionMessage = \"converting base64 certificate string to certificate object\"\r\n\r\n    $certificate = Get-MSEntraCertificate -CertificateBase64String $EntraIdCertificateBase64String -CertificatePassword $EntraIdCertificatePassword\r\n\r\n    Write-Verbose \"Converted base64 certificate string to certificate object\"\r\n\r\n    # Connect to Microsoft Exchange Online\r\n    # Docs: https://learn.microsoft.com/en-us/powershell/module/exchange/connect-exchangeonline?view=exchange-ps\r\n    $actionMessage = \"connecting to Microsoft Exchange Online\"\r\n\r\n    $createExchangeSessionSplatParams = @{\r\n        Organization          = $EntraIdOrganization\r\n        AppID                 = $EntraIdAppId\r\n        Certificate           = $certificate\r\n        CommandName           = $commands\r\n        ShowBanner            = $false\r\n        ShowProgress          = $false\r\n        TrackPerformance      = $false\r\n        SkipLoadingCmdletHelp = $true\r\n        SkipLoadingFormatData = $true\r\n        ErrorAction           = \"Stop\"\r\n    }\r\n\r\n    $null = Connect-ExchangeOnline @createExchangeSessionSplatParams\r\n\r\n    # Grant users permissions to shared mailbox\r\n    $actionMessage = \"granting permission [$permission] to shared mailbox to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for users\"\r\n    foreach ($userToAdd in $usersToAdd) {\r\n        switch ($permission) {\r\n            \"fullaccess\" {\r\n                # Grant Full Access to shared mailbox\r\n                try {\r\n                    $actionMessage = \"granting permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.userPrincipalName) ($($userToAdd.id))]\"\r\n\r\n                    $FullAccessPermissionSplatParams = @{\r\n                        Identity      = $mailbox.guid  # of $mailbox.UserPrincipalName\r\n                        User          = $userToAdd.id\r\n                        AccessRights  = \"FullAccess\"\r\n                        AutoMapping   = [bool]$AutoMapping\r\n                        ErrorAction   = \"Stop\"\r\n                        WarningAction = \"SilentlyContinue\"\r\n                    }\r\n                    $addFullAccessPermission = Add-MailboxPermission @FullAccessPermissionSplatParams\r\n\r\n                    # Send auditlog to HelloID\r\n                    $Log = @{\r\n                        Action            = \"GrantMembership\" # optional. ENUM (undefined = default) \r\n                        System            = \"Exchange\" # optional (free format text) \r\n                        Message           = \"Successfully granted permission [FullAccess] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.userPrincipalName) ($($userToAdd.id))]\" # required (free format text) \r\n                        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                        TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n                    }\r\n                    Write-Information -Tags \"Audit\" -MessageData $log\r\n                }\r\n                catch {\r\n                    $ex = $PSItem\r\n                    if (-not [string]::IsNullOrEmpty($ex.Exception.Data.RemoteException.Message)) {\r\n                        $warningMessage = \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Data.RemoteException.Message)\"\r\n                        $auditMessage = \"Error $($actionMessage). Error: $($ex.Exception.Data.RemoteException.Message)\"\r\n                    }\r\n                    else {\r\n                        $warningMessage = \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)\"\r\n                        $auditMessage = \"Error $($actionMessage). Error: $($ex.Exception.Message)\"\r\n                    }\r\n\r\n                    $Log = @{\r\n                        Action            = \"GrantMembership\" # optional. ENUM (undefined = default) \r\n                        System            = \"ExchangeOnline\" # optional (free format text) \r\n                        Message           = $auditMessage # required (free format text) \r\n                        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                        TargetDisplayName = $mailboxDisplayName # optional (free format text) \r\n                        TargetIdentifier  = $mailboxPrimarySmtpAddress # optional (free format text) \r\n                    }\r\n                    Write-Information -Tags \"Audit\" -MessageData $log\r\n                    Write-Warning $warningMessage\r\n                    Write-Error $auditMessage\r\n                }\r\n                break\r\n            }\r\n            \r\n            \"sendas\" {\r\n                # Grant Send As to shared mailbox\r\n                try {\r\n                    $actionMessage = \"granting permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.userPrincipalName) ($($userToAdd.id))]\"\r\n\r\n                    $sendAsPermissionSplatParams = @{\r\n                        Identity     = $mailbox.Guid\r\n                        Trustee      = $userToAdd.id\r\n                        AccessRights = \"SendAs\"\r\n                        Confirm      = $false\r\n                        ErrorAction  = \"Stop\"\r\n                    } \r\n                    $addSendAsPermission = Add-RecipientPermission @sendAsPermissionSplatParams\r\n\r\n                    # Send auditlog to HelloID\r\n                    $Log = @{\r\n                        Action            = \"GrantMembership\" # optional. ENUM (undefined = default) \r\n                        System            = \"Exchange\" # optional (free format text) \r\n                        Message           = \"Successfully granted permission [Send As] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.userPrincipalName) ($($userToAdd.id))\" # required (free format text) \r\n                        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                        TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n                    }\r\n                    Write-Information -Tags \"Audit\" -MessageData $log\r\n                }\r\n                catch {\r\n                    $ex = $PSItem\r\n                    if (-not [string]::IsNullOrEmpty($ex.Exception.Data.RemoteException.Message)) {\r\n                        $warningMessage = \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Data.RemoteException.Message)\"\r\n                        $auditMessage = \"Error $($actionMessage). Error: $($ex.Exception.Data.RemoteException.Message)\"\r\n                    }\r\n                    else {\r\n                        $warningMessage = \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)\"\r\n                        $auditMessage = \"Error $($actionMessage). Error: $($ex.Exception.Message)\"\r\n                    }\r\n\r\n                    $Log = @{\r\n                        Action            = \"GrantMembership\" # optional. ENUM (undefined = default) \r\n                        System            = \"ExchangeOnline\" # optional (free format text) \r\n                        Message           = $auditMessage # required (free format text) \r\n                        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                        TargetDisplayName = $mailboxDisplayName # optional (free format text) \r\n                        TargetIdentifier  = $mailboxPrimarySmtpAddress # optional (free format text) \r\n                    }\r\n                    Write-Information -Tags \"Audit\" -MessageData $log\r\n                    Write-Warning $warningMessage\r\n                    Write-Error $auditMessage\r\n                }\r\n                break\r\n            }\r\n\r\n            \"sendonbehalf\" {\r\n                # Grant Send on Behalf to shared mailbox\r\n                try {\r\n                    $actionMessage = \"granting permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.userPrincipalName) ($($userToAdd.id))]\"\r\n\r\n                    $SendonBehalfPermissionSplatParams = @{\r\n                        Identity            = $mailbox.Guid\r\n                        GrantSendOnBehalfTo = @{ add = \"$($userToAdd.id)\" }\r\n                        Confirm             = $false\r\n                        ErrorAction         = \"Stop\"\r\n                    }\r\n                    Write-Warning ($SendonBehalfPermissionSplatParams | ConvertTo-Json -Depth 10)\r\n                    $addSendonBehalfPermission = Set-Mailbox @SendonBehalfPermissionSplatParams\r\n\r\n                    # Send auditlog to HelloID\r\n                    $Log = @{\r\n                        Action            = \"GrantMembership\" # optional. ENUM (undefined = default) \r\n                        System            = \"Exchange\" # optional (free format text) \r\n                        Message           = \"Successfully granted permission [Send on Behalf] to mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToAdd.userPrincipalName) ($($userToAdd.id))]\" # required (free format text) \r\n                        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                        TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n                    }\r\n                    Write-Information -Tags \"Audit\" -MessageData $log\r\n                }\r\n                catch {\r\n                    $ex = $PSItem\r\n                    if (-not [string]::IsNullOrEmpty($ex.Exception.Data.RemoteException.Message)) {\r\n                        $warningMessage = \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Data.RemoteException.Message)\"\r\n                        $auditMessage = \"Error $($actionMessage). Error: $($ex.Exception.Data.RemoteException.Message)\"\r\n                    }\r\n                    else {\r\n                        $warningMessage = \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)\"\r\n                        $auditMessage = \"Error $($actionMessage). Error: $($ex.Exception.Message)\"\r\n                    }\r\n\r\n                    $Log = @{\r\n                        Action            = \"GrantMembership\" # optional. ENUM (undefined = default) \r\n                        System            = \"ExchangeOnline\" # optional (free format text) \r\n                        Message           = $auditMessage # required (free format text) \r\n                        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                        TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n                    }\r\n                    Write-Information -Tags \"Audit\" -MessageData $log\r\n                    Write-Warning $warningMessage\r\n                    Write-Error $auditMessage\r\n                }\r\n                break\r\n            }\r\n        }\r\n    }\r\n\r\n    # Revoke users permissions to shared mailbox\r\n    $actionMessage = \"revoking permission [$permission] from shared mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for users\"\r\n    foreach ($userToRemove in $usersToRemove) {\r\n        switch ($permission) {\r\n            \"fullaccess\" {\r\n                # Revoke Full Access from shared mailbox\r\n                try {\r\n                    $actionMessage = \"revoking permission [FullAccess] from mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.userPrincipalName) ($($userToRemove.id))]\"\r\n\r\n                    $FullAccessPermissionSplatParams = @{\r\n                        Identity      = $mailbox.Guid\r\n                        User          = $userToRemove.id\r\n                        AccessRights  = \"FullAccess\"\r\n                        ErrorAction   = \"Stop\"\r\n                        Confirm       = $false\r\n                        WarningAction = \"SilentlyContinue\"\r\n                    } \r\n                    $removeFullAccessPermission = Remove-MailboxPermission @FullAccessPermissionSplatParams\r\n\r\n                    # Send auditlog to HelloID\r\n                    $Log = @{\r\n                        Action            = \"RevokeMembership\" # optional. ENUM (undefined = default) \r\n                        System            = \"Exchange\" # optional (free format text) \r\n                        Message           = \"Successfully revoked permission [FullAccess] from mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.userPrincipalName) ($($userToRemove.id))]\" # required (free format text) \r\n                        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                        TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n                    }\r\n                    Write-Information -Tags \"Audit\" -MessageData $log\r\n                }\r\n                catch {\r\n                    $ex = $PSItem\r\n                    if (-not [string]::IsNullOrEmpty($ex.Exception.Data.RemoteException.Message)) {\r\n                        $warningMessage = \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Data.RemoteException.Message)\"\r\n                        $auditMessage = \"Error $($actionMessage). Error: $($ex.Exception.Data.RemoteException.Message)\"\r\n                    }\r\n                    else {\r\n                        $warningMessage = \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)\"\r\n                        $auditMessage = \"Error $($actionMessage). Error: $($ex.Exception.Message)\"\r\n                    }\r\n\r\n                    $Log = @{\r\n                        Action            = \"RevokeMembership\" # optional. ENUM (undefined = default) \r\n                        System            = \"ExchangeOnline\" # optional (free format text) \r\n                        Message           = $auditMessage # required (free format text) \r\n                        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                        TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n                    }\r\n                    Write-Information -Tags \"Audit\" -MessageData $log\r\n                    Write-Warning $warningMessage\r\n                    Write-Error $auditMessage\r\n                }\r\n                break\r\n            }\r\n            \r\n            \"sendas\" {\r\n                # Revoke Send As from shared mailbox\r\n                try {\r\n                    $actionMessage = \"revoking permission [Send As] from mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.userPrincipalName) ($($userToRemove.id))]\"\r\n\r\n                    $sendAsPermissionSplatParams = @{\r\n                        Identity     = $mailbox.Guid\r\n                        Trustee      = $userToRemove.id\r\n                        AccessRights = \"SendAs\"\r\n                        Confirm      = $false\r\n                        ErrorAction  = \"Stop\"\r\n                    } \r\n                    $removeSendAsPermission = Remove-RecipientPermission @sendAsPermissionSplatParams\r\n\r\n                    # Send auditlog to HelloID\r\n                    $Log = @{\r\n                        Action            = \"RevokeMembership\" # optional. ENUM (undefined = default) \r\n                        System            = \"Exchange\" # optional (free format text) \r\n                        Message           = \"Successfully revoked permission [Send As] from mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.id))]\" # required (free format text) \r\n                        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                        TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n                    }\r\n                    Write-Information -Tags \"Audit\" -MessageData $log\r\n                }\r\n                catch {\r\n                    $ex = $PSItem\r\n                    if (-not [string]::IsNullOrEmpty($ex.Exception.Data.RemoteException.Message)) {\r\n                        $warningMessage = \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Data.RemoteException.Message)\"\r\n                        $auditMessage = \"Error $($actionMessage). Error: $($ex.Exception.Data.RemoteException.Message)\"\r\n                    }\r\n                    else {\r\n                        $warningMessage = \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)\"\r\n                        $auditMessage = \"Error $($actionMessage). Error: $($ex.Exception.Message)\"\r\n                    }\r\n\r\n                    $Log = @{\r\n                        Action            = \"RevokeMembership\" # optional. ENUM (undefined = default) \r\n                        System            = \"ExchangeOnline\" # optional (free format text) \r\n                        Message           = $auditMessage # required (free format text) \r\n                        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                        TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n                    }\r\n                    Write-Information -Tags \"Audit\" -MessageData $log\r\n                    Write-Warning $warningMessage\r\n                    Write-Error $auditMessage\r\n                }\r\n                break\r\n            }\r\n\r\n            \"sendonbehalf\" {\r\n                # Revoke Send on Behalf from shared mailbox\r\n                try {\r\n                    $actionMessage = \"revoking permission [Send on Behalf] from mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.id))]\"\r\n\r\n                    $SendonBehalfPermissionSplatParams = @{\r\n                        Identity            = $mailbox.Guid\r\n                        GrantSendOnBehalfTo = @{ remove = \"$($userToRemove.id)\" }\r\n                        Confirm             = $false\r\n                        ErrorAction         = \"Stop\"\r\n                    } \r\n                    $removeSendonBehalfPermission = Set-Mailbox @SendonBehalfPermissionSplatParams\r\n\r\n                    # Send auditlog to HelloID\r\n                    $Log = @{\r\n                        Action            = \"RevokeMembership\" # optional. ENUM (undefined = default) \r\n                        System            = \"Exchange\" # optional (free format text) \r\n                        Message           = \"Successfully revoked permission [Send on Behalf] from mailbox [$($mailbox.DisplayName) ($($mailbox.Guid))] for user [$($userToRemove.UserPrincipalName) ($($userToRemove.id))]\" # required (free format text) \r\n                        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                        TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n                    }\r\n                    Write-Information -Tags \"Audit\" -MessageData $log\r\n                }\r\n                catch {\r\n                    $ex = $PSItem\r\n                    if (-not [string]::IsNullOrEmpty($ex.Exception.Data.RemoteException.Message)) {\r\n                        $warningMessage = \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Data.RemoteException.Message)\"\r\n                        $auditMessage = \"Error $($actionMessage). Error: $($ex.Exception.Data.RemoteException.Message)\"\r\n                    }\r\n                    else {\r\n                        $warningMessage = \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)\"\r\n                        $auditMessage = \"Error $($actionMessage). Error: $($ex.Exception.Message)\"\r\n                    }\r\n\r\n                    $Log = @{\r\n                        Action            = \"RevokeMembership\" # optional. ENUM (undefined = default) \r\n                        System            = \"ExchangeOnline\" # optional (free format text) \r\n                        Message           = $auditMessage # required (free format text) \r\n                        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                        TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n                    }\r\n                    Write-Information -Tags \"Audit\" -MessageData $log\r\n                    Write-Warning $warningMessage\r\n                    Write-Error $auditMessage\r\n                }\r\n                break\r\n            }\r\n        }\r\n    }\r\n}\r\ncatch {\r\n    $ex = $PSItem\r\n    if (-not [string]::IsNullOrEmpty($ex.Exception.Data.RemoteException.Message)) {\r\n        $warningMessage = \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Data.RemoteException.Message)\"\r\n        $auditMessage = \"Error $($actionMessage). Error: $($ex.Exception.Data.RemoteException.Message)\"\r\n    }\r\n    else {\r\n        $warningMessage = \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)\"\r\n        $auditMessage = \"Error $($actionMessage). Error: $($ex.Exception.Message)\"\r\n    }\r\n\r\n    $Log = @{\r\n        # Action            = \"\" # optional. ENUM (undefined = default) \r\n        System            = \"ExchangeOnline\" # optional (free format text) \r\n        Message           = $auditMessage # required (free format text) \r\n        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n        TargetDisplayName = $mailbox.DisplayName # optional (free format text)\r\n        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text)\r\n    }\r\n    \r\n    Write-Information -Tags \"Audit\" -MessageData $log\r\n    Write-Warning $warningMessage\r\n    Write-Error $auditMessage\r\n}\r\nfinally {\r\n    # Docs: https://learn.microsoft.com/en-us/powershell/module/exchange/disconnect-exchangeonline?view=exchange-ps\r\n    $deleteExchangeSessionSplatParams = @{\r\n        Confirm     = $false\r\n        ErrorAction = \"Stop\"\r\n    }\r\n    $null = Disconnect-ExchangeOnline @deleteExchangeSessionSplatParams\r\n}","runInCloud":false}
'@ 

Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-pencil-square" -task $tmpTask -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

