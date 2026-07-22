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

    function Get-PIMJwtClaims {
        param([Parameter(Mandatory)] [string]$AccessToken)

        $parts = $AccessToken.Split('.')
        if ($parts.Length -lt 2) {
            return $null
        }

        $payload = $parts[1].Replace('-', '+').Replace('_', '/')
        switch ($payload.Length % 4) {
            2 { $payload += '==' }
            3 { $payload += '=' }
            1 { return $null }
        }

        try {
            $bytes = [Convert]::FromBase64String($payload)
            $json = [System.Text.Encoding]::UTF8.GetString($bytes)
            return ($json | ConvertFrom-Json -ErrorAction Stop)
        }
        catch {
            return $null
        }
    }

    function Get-PIMTokenPermissions {
        param([Parameter(Mandatory)] [string]$AccessToken)

        $claims = Get-PIMJwtClaims -AccessToken $AccessToken
        if (-not $claims) {
            return @()
        }

        $permissions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        if ($claims.scp) {
            foreach ($scope in ([string]$claims.scp -split '\s+')) {
                if (-not [string]::IsNullOrWhiteSpace($scope)) {
                    $null = $permissions.Add($scope)
                }
            }
        }

        if ($claims.roles) {
            foreach ($role in @($claims.roles)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$role)) {
                    $null = $permissions.Add([string]$role)
                }
            }
        }

        return @($permissions)
    }

    function Get-PIMRequiredPermissionsForRequest {
        param(
            [Parameter(Mandatory)] [string]$RequestMethod,
            [Parameter(Mandatory)] [string]$RequestUri
        )

        $path = $RequestUri
        if ($path -match '^https?://[^/]+/(?:v1\.0|beta)/(?<path>.+)$') {
            $path = $matches.path
        }

        $isWrite = $RequestMethod -ne 'GET'

        if ($path -match '^(roleManagement/directory/)') {
            if ($isWrite) {
                return @(
                    'RoleManagement.ReadWrite.Directory'
                )
            }

            return @(
                'RoleManagement.Read.Directory',
                'RoleManagement.ReadWrite.Directory',
                'RoleManagement.Read.All'
            )
        }

        if ($path -match '^policies/roleManagementPolicy(?:Assignments|s)') {
            if ($isWrite) {
                return @(
                    'RoleManagementPolicy.ReadWrite.Directory',
                    'RoleManagement.ReadWrite.Directory'
                )
            }

            return @(
                'RoleManagementPolicy.Read.Directory',
                'RoleManagementPolicy.ReadWrite.Directory',
                'RoleManagement.Read.Directory',
                'RoleManagement.ReadWrite.Directory',
                'RoleManagement.Read.All'
            )
        }

        if ($path -match '^groups(?:/|\?|$)') {
            if ($isWrite) {
                return @(
                    'Group.ReadWrite.All',
                    'Directory.ReadWrite.All',
                    'Directory.AccessAsUser.All'
                )
            }

            return @(
                'Group.Read.All',
                'Group.ReadWrite.All',
                'Directory.Read.All',
                'Directory.ReadWrite.All',
                'Directory.AccessAsUser.All'
            )
        }

        return @()
    }

    function Format-PIMPermissionPreview {
        param([Parameter(Mandatory)] [string[]]$Permissions)

        if (-not $Permissions -or $Permissions.Count -eq 0) {
            return '(none)'
        }

        $sorted = @($Permissions | Sort-Object -Unique)
        if ($sorted.Count -le 12) {
            return ($sorted -join ', ')
        }

        $head = @($sorted | Select-Object -First 12)
        return ('{0} ... (+{1} more)' -f ($head -join ', '), ($sorted.Count - 12))
    }

    function Write-PIMGraphResponsePreview {
        param(
            [Parameter(Mandatory)] [object]$GraphResponse,
            [Parameter(Mandatory)] [string]$RequestUri,
            [Parameter(Mandatory)] [bool]$IsExpandedCollection
        )

        if ($null -eq $GraphResponse) {
            Write-Verbose "Graph response for '$RequestUri' is null."
            return
        }

        if ($IsExpandedCollection) {
            $items = @($GraphResponse)
            Write-Verbose "Graph response for '$RequestUri' returned expanded collection count=$($items.Count)."

            if ($items.Count -gt 0) {
                $firstItem = $items[0]
                $firstItemProperties = @($firstItem.PSObject.Properties.Name | Sort-Object)
                if ($firstItemProperties.Count -gt 0) {
                    Write-Verbose "Graph response first item properties: $($firstItemProperties -join ', ')"
                }

                try {
                    $previewJson = ($firstItem | ConvertTo-Json -Depth 8 -Compress)
                    Write-Verbose "Graph response first item JSON: $previewJson"
                }
                catch {
                    Write-Verbose "Graph response first item could not be serialized for preview."
                }
            }

            return
        }

        $topLevelProperties = @($GraphResponse.PSObject.Properties.Name | Sort-Object)
        if ($topLevelProperties.Count -gt 0) {
            Write-Verbose "Graph response top-level properties for '$RequestUri': $($topLevelProperties -join ', ')"
        }

        if ($GraphResponse.PSObject.Properties['value']) {
            $items = @($GraphResponse.value)
            Write-Verbose "Graph response collection count=$($items.Count)."

            if ($items.Count -gt 0) {
                $firstItem = $items[0]
                $firstItemProperties = @($firstItem.PSObject.Properties.Name | Sort-Object)
                if ($firstItemProperties.Count -gt 0) {
                    Write-Verbose "Graph response first item properties: $($firstItemProperties -join ', ')"
                }

                try {
                    $previewJson = ($firstItem | ConvertTo-Json -Depth 8 -Compress)
                    Write-Verbose "Graph response first item JSON: $previewJson"
                }
                catch {
                    Write-Verbose "Graph response first item could not be serialized for preview."
                }
            }

            return
        }

        try {
            $previewJson = ($GraphResponse | ConvertTo-Json -Depth 8 -Compress)
            Write-Verbose "Graph response JSON for '$RequestUri': $previewJson"
        }
        catch {
            Write-Verbose "Graph response for '$RequestUri' could not be serialized for preview."
        }
    }

    function Assert-PIMTokenPermissionForRequest {
        param(
            [Parameter(Mandatory)] [string]$RequestMethod,
            [Parameter(Mandatory)] [string]$RequestUri,
            [Parameter(Mandatory)] [string]$AccessToken
        )

        $requiredAnyOf = @(Get-PIMRequiredPermissionsForRequest -RequestMethod $RequestMethod -RequestUri $RequestUri)
        if ($requiredAnyOf.Count -eq 0) {
            return
        }

        $tokenPermissions = @(Get-PIMTokenPermissions -AccessToken $AccessToken)
        if ($tokenPermissions.Count -eq 0) {
            Write-Verbose "Token permissions could not be inspected for '$RequestMethod $RequestUri'. Allowing request and deferring authorization validation to Microsoft Graph."
            return
        }

        $hasRequired = $false
        foreach ($permission in $requiredAnyOf) {
            if ($tokenPermissions -icontains $permission) {
                $hasRequired = $true
                break
            }
        }

        if (-not $hasRequired) {
            $present = Format-PIMPermissionPreview -Permissions $tokenPermissions
            throw "Missing permissions in access token for Graph request ($RequestMethod $RequestUri). Required any of: $($requiredAnyOf -join ', '). Token has: $present"
        }
    }

    Assert-PIMTokenPermissionForRequest -RequestMethod $Method -RequestUri $Uri -AccessToken $token

    try {
        $response = Invoke-RestMethod @params -ErrorAction Stop
        Write-PIMGraphResponsePreview -GraphResponse $response -RequestUri $Uri -IsExpandedCollection:$false

        if ($ExpandNextLink) {
            $allValues = [System.Collections.Generic.List[PSCustomObject]]::new()
            if ($response.value) {
                $allValues.AddRange([PSCustomObject[]]$response.value)
            }
            $nextLink = $response.'@odata.nextLink'
            $pageCount = 1
            while ($nextLink) {
                $params['Uri'] = $nextLink
                $params.Remove('Body') | Out-Null
                $page      = Invoke-RestMethod @params -ErrorAction Stop
                Write-PIMGraphResponsePreview -GraphResponse $page -RequestUri $nextLink -IsExpandedCollection:$false
                $pageCount++
                if ($page.value) {
                    $allValues.AddRange([PSCustomObject[]]$page.value)
                }
                $nextLink  = $page.'@odata.nextLink'
            }

            if ($pageCount -gt 1) {
                Write-PIMGraphResponsePreview -GraphResponse @($allValues) -RequestUri $Uri -IsExpandedCollection:$true
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
