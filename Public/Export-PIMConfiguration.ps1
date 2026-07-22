function Export-PIMConfiguration {
    <#
    .SYNOPSIS
        Backs up current PIM configuration for roles and groups to a JSON file.
    .DESCRIPTION
        Exports role policy settings, group policy settings, and role-to-group
        assignments in a format that can be restored with Invoke-PIMConfiguration
        (or Restore-PIMConfiguration).
    .PARAMETER OutputFile
        Path to write the backup JSON file.
    .PARAMETER IncludeRoles
        Include Entra role policy backups.
    .PARAMETER IncludeGroups
        Include group policy backups and role-to-group assignments.
    .PARAMETER IncludeRoleToGroupAssignments
        Include role-to-group assignments section.
    .PARAMETER IncludeUnmodified
        Include items even when they do not expose a modified date.
        By default, only items with a modified date are exported.
    .PARAMETER PassThru
        Returns the backup object in addition to writing the file.
    .PARAMETER Parallel
        Enable parallel retrieval for role and group policy exports.
    .PARAMETER ThrottleLimit
        Maximum number of concurrent workers when -Parallel is used.
    .PARAMETER MaxResults
        Limits the number of exported items per section. Useful for debugging.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)]
        [string]$OutputFile,

        [Parameter()]
        [switch]$IncludeRoles,

        [Parameter()]
        [switch]$IncludeGroups,

        [Parameter()]
        [switch]$IncludeRoleToGroupAssignments,

        [Parameter()]
        [switch]$IncludeUnmodified,

        [Parameter()]
        [switch]$PassThru,

        [Parameter()]
        [switch]$Parallel,

        [Parameter()]
        [ValidateRange(1, 100)]
        [int]$ThrottleLimit = 4,

        [Parameter()]
        [ValidateRange(1, 1000)]
        [Nullable[int]]$MaxResults
    )

    if (-not $IncludeRoles -and -not $IncludeGroups -and -not $IncludeRoleToGroupAssignments) {
        $IncludeRoles = $true
        $IncludeGroups = $true
        $IncludeRoleToGroupAssignments = $true
    }

    $backup = [ordered]@{}
    $roleDisplayNameById = @{}

    function Test-PIMHasModifiedDate {
        param([Parameter(Mandatory)][object]$InputObject)

        $candidateProperties = @('modifiedDateTime', 'lastModifiedDateTime', 'modifiedDate', 'lastModifiedDate')
        foreach ($name in $candidateProperties) {
            $prop = $InputObject.PSObject.Properties[$name]
            if ($null -ne $prop) {
                $value = $prop.Value
                if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                    return $true
                }
            }
        }

        return $false
    }

    function Test-PIMPermissionError {
        param([Parameter(Mandatory)][object]$ErrorRecord)

        $text = [string]$ErrorRecord
        return $text -match 'Missing permissions in access token|PermissionScopeNotGranted|missing permission scope'
    }

    function Test-PIMPolicyHasExplicitModification {
        param([Parameter(Mandatory)][object]$PolicyObject)

        if (Test-PIMHasModifiedDate -InputObject $PolicyObject) {
            return $true
        }

        $modifierProperty = $PolicyObject.PSObject.Properties['lastModifiedBy']
        if ($null -eq $modifierProperty -or $null -eq $modifierProperty.Value) {
            return $false
        }

        $modifier = $modifierProperty.Value
        foreach ($propertyName in @('displayName', 'id')) {
            $property = $modifier.PSObject.Properties[$propertyName]
            if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
                return $true
            }
        }

        foreach ($nestedName in @('user', 'application')) {
            $nestedProperty = $modifier.PSObject.Properties[$nestedName]
            if ($null -eq $nestedProperty -or $null -eq $nestedProperty.Value) {
                continue
            }

            foreach ($propertyName in @('displayName', 'id')) {
                $property = $nestedProperty.Value.PSObject.Properties[$propertyName]
                if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
                    return $true
                }
            }
        }

        return $false
    }

    function Resolve-PIMGroupIdFromScopeId {
        param([Parameter(Mandatory)][string]$ScopeId)

        if ($ScopeId -match '^/groups/(?<id>[0-9a-fA-F-]{36})$') {
            return $matches.id
        }

        if ($ScopeId -match '^(?<id>[0-9a-fA-F-]{36})$') {
            return $matches.id
        }

        if ($ScopeId -match '^/(?<id>[0-9a-fA-F-]{36})$') {
            return $matches.id
        }

        return $null
    }

    function Split-PIMItemsIntoChunks {
        param(
            [Parameter(Mandatory)] [object[]]$Items,
            [Parameter(Mandatory)] [int]$MaxChunkSize
        )

        $chunks = [System.Collections.Generic.List[object[]]]::new()
        if (-not $Items -or $Items.Count -eq 0) {
            return @()
        }

        $index = 0
        while ($index -lt $Items.Count) {
            $last = [Math]::Min($index + $MaxChunkSize - 1, $Items.Count - 1)
            $chunks.Add(@($Items[$index..$last]))
            $index = $last + 1
        }

        return @($chunks)
    }

    function Select-PIMLimitedItems {
        param(
            [Parameter()] [AllowEmptyCollection()] [object[]]$Items = @(),
            [Parameter(Mandatory)] [string]$Label,
            [Parameter(Mandatory)] [int]$Limit
        )

        $result = @($Items)
        if ($result.Count -gt $Limit) {
            Write-Verbose "Limiting $Label to first $Limit item(s)."
            $result = @($result | Select-Object -First $Limit)
        }

        return $result
    }

    function Invoke-PIMPolicyFetchParallel {
        param(
            [Parameter(Mandatory)] [ValidateSet('Role', 'Group')] [string]$TargetType,
            [Parameter(Mandatory)] [string[]]$Ids,
            [Parameter(Mandatory)] [int]$MaxConcurrency
        )

        if ($Ids.Count -eq 0) {
            return @()
        }

        $threadJobCommand = Get-Command Start-ThreadJob -ErrorAction SilentlyContinue
        if (-not $threadJobCommand) {
            Write-Verbose 'Start-ThreadJob is unavailable. Falling back to serial policy retrieval.'
            if ($TargetType -eq 'Role') {
                return @(Get-PIMRolePolicy -RoleDefinitionId $Ids -SuppressPermissionWarnings)
            }
            return @(Get-PIMGroupPolicy -GroupId $Ids -SuppressPermissionWarnings)
        }

        $moduleManifestPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'PaC.psd1'
        $normalizedToken = Resolve-PIMAccessToken -InputObject $script:PIMContext.AccessToken

        $chunkSize = [Math]::Ceiling($Ids.Count / $MaxConcurrency)
        if ($chunkSize -lt 1) { $chunkSize = 1 }
        $chunks = Split-PIMItemsIntoChunks -Items $Ids -MaxChunkSize $chunkSize

        Write-Verbose "Running $TargetType policy retrieval in parallel across $($chunks.Count) worker chunk(s) with throttle $MaxConcurrency."

        $jobs = [System.Collections.Generic.List[object]]::new()
        $results = [System.Collections.Generic.List[object]]::new()

        $scriptBlock = {
            param(
                [string]$ModulePath,
                [string]$AccessToken,
                [string[]]$ChunkIds,
                [string]$Type
            )

            Import-Module $ModulePath -Force | Out-Null
            $module = Get-Module PaC
            $module.SessionState.PSVariable.Set('PIMContext', @{
                TenantId    = $null
                ClientId    = $null
                AccessToken = $AccessToken
                ExpiresAt   = $null
                AuthMethod  = 'AccessToken'
            })

            if ($Type -eq 'Role') {
                return @(Get-PIMRolePolicy -RoleDefinitionId $ChunkIds -SuppressPermissionWarnings)
            }

            return @(Get-PIMGroupPolicy -GroupId $ChunkIds -SuppressPermissionWarnings)
        }

        try {
            foreach ($chunk in $chunks) {
                $job = Start-ThreadJob -ScriptBlock $scriptBlock -ArgumentList $moduleManifestPath, $normalizedToken, @($chunk), $TargetType
                $jobs.Add($job) | Out-Null
            }

            while ($jobs.Count -gt 0) {
                $completed = Wait-Job -Job @($jobs) -Any
                if (-not $completed) {
                    continue
                }

                try {
                    $jobOutput = Receive-Job -Job $completed -ErrorAction Stop
                    if ($jobOutput) {
                        foreach ($item in @($jobOutput)) {
                            $results.Add($item) | Out-Null
                        }
                    }
                }
                finally {
                    Remove-Job -Job $completed -Force -ErrorAction SilentlyContinue
                    $remainingJobs = [System.Collections.Generic.List[object]]::new()
                    foreach ($job in @($jobs | Where-Object { $_.Id -ne $completed.Id })) {
                        $remainingJobs.Add($job) | Out-Null
                    }
                    $jobs = $remainingJobs
                }
            }
        }
        catch {
            Write-Warning "Parallel $TargetType policy retrieval failed. Falling back to serial retrieval. $_"

            foreach ($job in @($jobs)) {
                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
            }

            if ($TargetType -eq 'Role') {
                return @(Get-PIMRolePolicy -RoleDefinitionId $Ids -SuppressPermissionWarnings)
            }

            return @(Get-PIMGroupPolicy -GroupId $Ids -SuppressPermissionWarnings)
        }

        return @($results)
    }

    if ($IncludeRoles -or $IncludeRoleToGroupAssignments) {
        try {
            foreach ($rd in @(Get-PIMRoleDefinition -All)) {
                if ($rd.id -and $rd.displayName) {
                    $roleDisplayNameById[$rd.id] = $rd.displayName
                }
            }
        }
        catch {
            Write-Warning "Failed to build role definition lookup table: $_"
        }
    }

    if ($IncludeRoles) {
        $rolePolicies = [System.Collections.Generic.List[object]]::new()
        $roleDefinitionIdsToExport = $null
        $rolePrefilterApplied = $false

        if (-not $IncludeUnmodified) {
            try {
                $assignmentFilter = "scopeId eq '/' and scopeType eq 'DirectoryRole'"
                $assignmentUri = "policies/roleManagementPolicyAssignments?`$filter=$([uri]::EscapeDataString($assignmentFilter))&`$select=roleDefinitionId,policyId"
                $assignments = @(Invoke-PIMGraphRequest -Method GET -Uri $assignmentUri -ExpandNextLink)

                $roleIdsByPolicyId = @{}
                foreach ($assignment in $assignments) {
                    $roleId = [string]$assignment.roleDefinitionId
                    $policyId = [string]$assignment.policyId
                    if ([string]::IsNullOrWhiteSpace($roleId) -or [string]::IsNullOrWhiteSpace($policyId)) {
                        continue
                    }

                    if (-not $roleIdsByPolicyId.ContainsKey($policyId)) {
                        $roleIdsByPolicyId[$policyId] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                    }

                    $null = $roleIdsByPolicyId[$policyId].Add($roleId)
                }

                $modifiedRoleDefinitionIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                $policyFilter = "scopeType eq 'DirectoryRole' and scopeId eq '/'"
                $policyUri = "policies/roleManagementPolicies?`$filter=$([uri]::EscapeDataString($policyFilter))&`$select=id,lastModifiedDateTime,lastModifiedBy,scopeId,scopeType"
                $policyMetadataCollection = @(Invoke-PIMGraphRequest -Method GET -Uri $policyUri -ExpandNextLink)

                foreach ($policyMetadata in $policyMetadataCollection) {
                    $policyId = [string]$policyMetadata.id
                    if ([string]::IsNullOrWhiteSpace($policyId) -or -not $roleIdsByPolicyId.ContainsKey($policyId)) {
                        continue
                    }

                    if (Test-PIMPolicyHasExplicitModification -PolicyObject $policyMetadata) {
                        foreach ($roleId in @($roleIdsByPolicyId[$policyId])) {
                            $null = $modifiedRoleDefinitionIds.Add($roleId)
                        }
                    }
                }

                if ($policyMetadataCollection.Count -gt 0) {
                    $roleDefinitionIdsToExport = @($modifiedRoleDefinitionIds)
                    $rolePrefilterApplied = $true
                    Write-Verbose "Role prefilter selected $($roleDefinitionIdsToExport.Count) modified role definition(s) from $($policyMetadataCollection.Count) role management policy record(s)."
                }
                else {
                    Write-Verbose 'Role prefilter unavailable (role management policies query returned no metadata). Falling back to full role policy retrieval.'
                }
            }
            catch {
                Write-Verbose 'Role prefilter unavailable. Falling back to full role policy retrieval.'
            }
        }

        try {
            if ($Parallel) {
                $parallelRoleIds = @()
                if ($null -ne $roleDefinitionIdsToExport) {
                    $parallelRoleIds = @($roleDefinitionIdsToExport)
                }
                else {
                    $parallelRoleIds = @(Get-PIMRoleDefinition | Where-Object { $_.id } | Select-Object -ExpandProperty id -Unique)
                    if ($null -ne $MaxResults) {
                        $parallelRoleIds = @(Select-PIMLimitedItems -Items $parallelRoleIds -Label 'role policy candidates' -Limit $MaxResults.Value)
                    }
                }

                if ($parallelRoleIds.Count -eq 0) {
                    $policies = @()
                }
                else {
                    $policies = @(Invoke-PIMPolicyFetchParallel -TargetType Role -Ids $parallelRoleIds -MaxConcurrency $ThrottleLimit)
                }
            }
            elseif ($null -ne $roleDefinitionIdsToExport) {
                if ($roleDefinitionIdsToExport.Count -eq 0) {
                    $policies = @()
                }
                else {
                    $policies = @(Get-PIMRolePolicy -RoleDefinitionId $roleDefinitionIdsToExport -SuppressPermissionWarnings)
                }
            }
            else {
                if ($null -ne $MaxResults) {
                    $limitedRoleIds = @(Get-PIMRoleDefinition | Where-Object { $_.id } | Select-Object -ExpandProperty id -Unique)
                    $limitedRoleIds = @(Select-PIMLimitedItems -Items $limitedRoleIds -Label 'role policy candidates' -Limit $MaxResults.Value)

                    if ($limitedRoleIds.Count -eq 0) {
                        $policies = @()
                    }
                    else {
                        $policies = @(Get-PIMRolePolicy -RoleDefinitionId $limitedRoleIds -SuppressPermissionWarnings)
                    }
                }
                else {
                    $policies = @(Get-PIMRolePolicy -SuppressPermissionWarnings)
                }
            }
        }
        catch {
            if (Test-PIMPermissionError -ErrorRecord $_) {
                Write-Warning 'Skipping role policy export because the token is missing required Graph role-management permissions. Grant/admin-consent RoleManagement.Read.Directory and RoleManagementPolicy.Read.Directory (or their read-write equivalents), then reconnect.'
                $policies = @()
            }
            else {
                throw
            }
        }

        $policiesToExport = @($policies)
        if (-not $IncludeUnmodified -and -not $rolePrefilterApplied) {
            $policiesToExport = @($policiesToExport | Where-Object { Test-PIMHasModifiedDate -InputObject $_ })

            if ($policiesToExport.Count -eq 0 -and @($policies).Count -gt 0) {
                Write-Verbose 'Role policies do not expose modified-date fields. Exporting all retrieved role policies to avoid an empty backup.'
                $policiesToExport = @($policies)
            }
        }

        if ($null -ne $MaxResults) {
            $policiesToExport = @(Select-PIMLimitedItems -Items $policiesToExport -Label 'role policy results' -Limit $MaxResults.Value)
        }

        Write-Verbose "Role export retrieved $(@($policies).Count) policy object(s); exporting $(@($policiesToExport).Count)."

        foreach ($policy in @($policiesToExport)) {
            try {
                if (-not $policy) {
                    continue
                }

                $settings = ConvertFrom-PIMPolicyToSettings -Policy $policy
                if ($settings.Count -eq 0) {
                    continue
                }

                $roleName = [string]$policy.RoleName
                if ([string]::IsNullOrWhiteSpace($roleName)) {
                    $roleName = [string]$policy.id
                }

                $rolePolicies.Add([ordered]@{
                    RoleName             = $roleName
                    LastModifiedDateTime = $policy.lastModifiedDateTime
                    LastModifiedBy       = $policy.lastModifiedBy
                    Settings             = $settings
                })
            }
            catch {
                $roleLabel = if ($policy -and $policy.RoleName) { $policy.RoleName } else { '<unknown role>' }
                Write-Warning "Failed to export role policy for '$roleLabel': $_"
            }
        }

        $backup['EntraRoles'] = @{ Policies = @($rolePolicies) }
    }

    $assignableGroups = @()
    if ($IncludeGroups -or $IncludeRoleToGroupAssignments) {
        try {
            $groupsUri = "groups?`$filter=$([uri]::EscapeDataString('isAssignableToRole eq true'))&`$select=id,displayName,isAssignableToRole,modifiedDateTime"
            $assignableGroups = @(Invoke-PIMGraphRequest -Method GET -Uri $groupsUri -ExpandNextLink)
        }
        catch {
            Write-Warning "Failed to enumerate role-assignable groups: $_"
        }
    }

    if ($IncludeGroups) {
        $groupPolicies = [System.Collections.Generic.List[object]]::new()
        $groupIdsToExport = $null
        $groupPrefilterApplied = $false

        if (-not $IncludeUnmodified) {
            try {
                $modifiedGroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

                foreach ($groupMetadata in @($assignableGroups)) {
                    $groupId = [string]$groupMetadata.id
                    if ([string]::IsNullOrWhiteSpace($groupId)) {
                        continue
                    }

                    if (Test-PIMHasModifiedDate -InputObject $groupMetadata) {
                        $null = $modifiedGroupIds.Add($groupId)
                    }
                }

                if ($modifiedGroupIds.Count -gt 0) {
                    $groupIdsToExport = @($modifiedGroupIds)
                    $groupPrefilterApplied = $true
                    Write-Verbose "Group prefilter selected $($groupIdsToExport.Count) modified group(s) from role-assignable group metadata."
                }
                else {
                    Write-Verbose 'Group prefilter unavailable (no modifiedDateTime on role-assignable groups). Falling back to full group policy retrieval.'
                }
            }
            catch {
                Write-Verbose 'Group prefilter unavailable. Falling back to full group policy retrieval.'
            }
        }

        try {
            if ($Parallel) {
                $parallelGroupIds = @()
                if ($null -ne $groupIdsToExport) {
                    $parallelGroupIds = @($groupIdsToExport)
                }
                else {
                    $parallelGroupIds = @($assignableGroups |
                        Where-Object { $_.isAssignableToRole -eq $true } |
                        Select-Object -ExpandProperty id |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                        Select-Object -Unique)
                    if ($null -ne $MaxResults) {
                        $parallelGroupIds = @(Select-PIMLimitedItems -Items $parallelGroupIds -Label 'group policy candidates' -Limit $MaxResults.Value)
                    }
                }

                if ($parallelGroupIds.Count -eq 0) {
                    $policies = @()
                }
                else {
                    $policies = @(Invoke-PIMPolicyFetchParallel -TargetType Group -Ids $parallelGroupIds -MaxConcurrency $ThrottleLimit)
                }
            }
            elseif ($null -ne $groupIdsToExport) {
                if ($groupIdsToExport.Count -eq 0) {
                    $policies = @()
                }
                else {
                    $policies = @(Get-PIMGroupPolicy -GroupId $groupIdsToExport -SuppressPermissionWarnings)
                }
            }
            else {
                if ($null -ne $MaxResults) {
                    $limitedGroupIds = @($assignableGroups | Where-Object { $_.id } | Select-Object -ExpandProperty id -Unique)
                    $limitedGroupIds = @(Select-PIMLimitedItems -Items $limitedGroupIds -Label 'group policy candidates' -Limit $MaxResults.Value)

                    if ($limitedGroupIds.Count -eq 0) {
                        $policies = @()
                    }
                    else {
                        $policies = @(Get-PIMGroupPolicy -GroupId $limitedGroupIds -SuppressPermissionWarnings)
                    }
                }
                else {
                    $policies = @(Get-PIMGroupPolicy -SuppressPermissionWarnings)
                }
            }
        }
        catch {
            if (Test-PIMPermissionError -ErrorRecord $_) {
                Write-Warning 'Skipping group policy export because the token is missing required Graph role-management permissions. Grant/admin-consent RoleManagementPolicy.Read.Directory (or read-write equivalent), then reconnect.'
                $policies = @()
            }
            else {
                throw
            }
        }

        $policiesToExport = @($policies)
        if (-not $IncludeUnmodified -and -not $groupPrefilterApplied) {
            $policiesToExport = @($policiesToExport | Where-Object { Test-PIMHasModifiedDate -InputObject $_ })

            if ($policiesToExport.Count -eq 0 -and @($policies).Count -gt 0) {
                Write-Verbose 'Group policies do not expose modified-date fields. Exporting all retrieved group policies to avoid an empty backup.'
                $policiesToExport = @($policies)
            }
        }

        if ($null -ne $MaxResults) {
            $policiesToExport = @(Select-PIMLimitedItems -Items $policiesToExport -Label 'group policy results' -Limit $MaxResults.Value)
        }

        Write-Verbose "Group export retrieved $(@($policies).Count) policy object(s); exporting $(@($policiesToExport).Count)."

        foreach ($policy in @($policiesToExport)) {
            try {
                if (-not $policy) {
                    continue
                }

                $settings = ConvertFrom-PIMPolicyToSettings -Policy $policy
                if ($settings.Count -eq 0) {
                    continue
                }

                $groupName = [string]$policy.GroupName
                $groupId = [string]$policy.GroupId

                if ([string]::IsNullOrWhiteSpace($groupName)) {
                    $groupName = $groupId
                }

                $groupPolicies.Add([ordered]@{
                    GroupName            = $groupName
                    GroupId              = $groupId
                    LastModifiedDateTime = $policy.lastModifiedDateTime
                    LastModifiedBy       = $policy.lastModifiedBy
                    Settings             = $settings
                })
            }
            catch {
                $groupLabel = if ($policy -and $policy.GroupName) { $policy.GroupName } else { '<unknown group>' }
                Write-Warning "Failed to export group policy for '$groupLabel': $_"
            }
        }

        $backup['GroupPolicies'] = @($groupPolicies)
    }

    if ($IncludeRoleToGroupAssignments) {
        $roleAssignmentsByGroup = [System.Collections.Generic.List[object]]::new()
        $assignmentPermissionWarningShown = $false

        foreach ($group in $assignableGroups) {
            try {
                $filter = "principalId eq '$($group.id)'"
                $uri = "roleManagement/directory/roleAssignments?`$filter=$([uri]::EscapeDataString($filter))"
                $assignments = @(Invoke-PIMGraphRequest -Method GET -Uri $uri -ExpandNextLink)

                if ($assignments.Count -eq 0) {
                    continue
                }

                $roleDefinitionIds = @($assignments | ForEach-Object { $_.roleDefinitionId } | Where-Object { $_ } | Select-Object -Unique)
                if ($roleDefinitionIds.Count -eq 0) {
                    continue
                }

                $directoryScopeIds = @($assignments |
                    ForEach-Object { [string]$_.directoryScopeId } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                    Select-Object -Unique)

                $roleNames = @()
                foreach ($roleDefinitionId in $roleDefinitionIds) {
                    if ($roleDisplayNameById.ContainsKey($roleDefinitionId)) {
                        $roleNames += $roleDisplayNameById[$roleDefinitionId]
                        continue
                    }

                    # Fallback: try direct lookup once without emitting warnings.
                    try {
                        $rd = Invoke-PIMGraphRequest -Method GET -Uri "roleManagement/directory/roleDefinitions/$roleDefinitionId"
                        if ($rd -and $rd.displayName) {
                            $roleNames += $rd.displayName
                            $roleDisplayNameById[$roleDefinitionId] = $rd.displayName
                        }
                    }
                    catch {
                        # Keep export resilient when a role definition no longer exists
                        # or is inaccessible for the current token.
                    }
                }

                $roleAssignmentsByGroup.Add(@{
                    GroupName         = $group.displayName
                    GroupId           = $group.id
                    DirectoryScopeIds = $directoryScopeIds
                    RoleDefinitionIds = $roleDefinitionIds
                    RoleNames         = @($roleNames | Select-Object -Unique)
                })
            }
            catch {
                if (Test-PIMPermissionError -ErrorRecord $_) {
                    if (-not $assignmentPermissionWarningShown) {
                        Write-Warning 'Stopping role-to-group assignment export due to insufficient Graph permissions for role management endpoints. This warning is shown once.'
                        $assignmentPermissionWarningShown = $true
                    }
                    break
                }

                Write-Warning "Failed to export role-to-group assignments for '$($group.displayName)': $_"
            }
        }

        $assignmentResults = @($roleAssignmentsByGroup)
        if ($null -ne $MaxResults) {
            $assignmentResults = @(Select-PIMLimitedItems -Items $assignmentResults -Label 'role-to-group assignment results' -Limit $MaxResults.Value)
        }

        Write-Verbose "Role-to-group export retrieved $($roleAssignmentsByGroup.Count) assignment mapping(s); exporting $(@($assignmentResults).Count)."

        $backup['RoleToGroupAssignments'] = @($assignmentResults)
    }

    $dir = Split-Path -Path $OutputFile -Parent
    if ($dir -and -not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }

    $backupObject = [pscustomobject]$backup
    $backupObject | ConvertTo-Json -Depth 30 | Set-Content -Path $OutputFile -Encoding UTF8

    Write-Host "PIM configuration backup written to '$OutputFile'." -ForegroundColor Green

    if ($PassThru) {
        return $backupObject
    }
}
