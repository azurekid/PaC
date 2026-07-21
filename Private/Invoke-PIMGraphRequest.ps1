function Invoke-PIMGraphRequest {
    <#
    .SYNOPSIS
        Sends an authenticated request to the Microsoft Graph API.
    .DESCRIPTION
        Internal helper that wraps Invoke-RestMethod with the current PIM context
        (access token) and handles paging via @odata.nextLink automatically.
    .PARAMETER Method
        HTTP method (GET, POST, PATCH, DELETE).
    .PARAMETER Uri
        Graph API URI (relative path or full URL).
    .PARAMETER Body
        Request body (hashtable or PSObject) serialised to JSON automatically.
    .PARAMETER ExpandNextLink
        When specified, follows @odata.nextLink to retrieve all pages.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter()]
        [object]$Body,

        [Parameter()]
        [switch]$ExpandNextLink
    )

    if (-not $script:PIMContext) {
        throw 'Not connected to Microsoft Graph. Run Connect-PIM first.'
    }

    $token = Resolve-PIMAccessToken -InputObject $script:PIMContext.AccessToken
    $script:PIMContext.AccessToken = $token

    $baseUri = 'https://graph.microsoft.com/beta'
    if ($Uri -notmatch '^https?://') {
        $Uri = "$baseUri/$($Uri.TrimStart('/'))"
    }

    $headers = @{
        Authorization  = "Bearer $token"
        'Content-Type' = 'application/json'
        'Accept'       = 'application/json'
    }

    $params = @{
        Method  = $Method
        Uri     = $Uri
        Headers = $headers
    }

    if ($Body) {
        $params['Body'] = ($Body | ConvertTo-Json -Depth 20 -Compress)
    }

    function Get-GraphErrorFromException {
        param([Parameter(Mandatory)] $ExceptionRecord)

        if ($ExceptionRecord.ErrorDetails -and $ExceptionRecord.ErrorDetails.Message) {
            try {
                return ($ExceptionRecord.ErrorDetails.Message | ConvertFrom-Json -ErrorAction Stop)
            }
            catch { }
        }

        if ($ExceptionRecord.Exception.Response) {
            try {
                $reader  = [System.IO.StreamReader]::new($ExceptionRecord.Exception.Response.GetResponseStream())
                $content = $reader.ReadToEnd()
                if ($content) {
                    return ($content | ConvertFrom-Json -ErrorAction Stop)
                }
            }
            catch { }
        }

        return $null
    }

    function Get-PIMPermissionGuidance {
        param(
            [Parameter(Mandatory)] [string]$RequestMethod,
            [Parameter(Mandatory)] [string]$RequestUri
        )

        $isRoleManagement = $RequestUri -match 'roleManagement/directory|roleManagementPolicies|roleManagementPolicyAssignments'
        if (-not $isRoleManagement) {
            return $null
        }

        if ($RequestMethod -eq 'GET') {
            return 'Required Graph permissions (delegated or application): RoleManagement.Read.Directory (or RoleManagement.Read.All). For policy endpoints, RoleManagementPolicy.Read.Directory may also be required.'
        }

        return 'Required Graph permissions (delegated or application): RoleManagement.ReadWrite.Directory and, for policy endpoints, RoleManagementPolicy.ReadWrite.Directory.'
    }

    try {
        $response = Invoke-RestMethod @params -ErrorAction Stop

        if ($ExpandNextLink) {
            $allValues = [System.Collections.Generic.List[PSCustomObject]]::new()
            if ($response.value) {
                $allValues.AddRange([PSCustomObject[]]$response.value)
            }
            $nextLink = $response.'@odata.nextLink'
            while ($nextLink) {
                $params['Uri'] = $nextLink
                $params.Remove('Body') | Out-Null
                $page      = Invoke-RestMethod @params -ErrorAction Stop
                if ($page.value) {
                    $allValues.AddRange([PSCustomObject[]]$page.value)
                }
                $nextLink  = $page.'@odata.nextLink'
            }
            return $allValues
        }

        return $response
    }
    catch {
        $graphError = Get-GraphErrorFromException -ExceptionRecord $_
        $errorMessage = $_.Exception.Message

        if ($graphError -and $graphError.error) {
            $errorMessage = $graphError.error.message

            $isPermissionScopeError = $graphError.error.code -eq 'PermissionScopeNotGranted' -or $graphError.error.message -match 'PermissionScopeNotGranted|Authorization failed due to missing permission scope'
            if ($isPermissionScopeError) {
                $guidance = Get-PIMPermissionGuidance -RequestMethod $Method -RequestUri $Uri
                $recommendation = @(
                    'Graph token does not include required role-management permissions.',
                    $guidance,
                    'If using delegated auth, reconnect with device code using an app registration that has these delegated permissions granted and admin consented.',
                    'If using app-only auth, grant and admin-consent the corresponding application permissions on the app registration.'
                ) -join ' '

                throw "Graph API request failed ($Method $Uri): $errorMessage $recommendation"
            }
        }

        Write-Error "Graph API request failed ($Method $Uri): $errorMessage"
        throw
    }
}
