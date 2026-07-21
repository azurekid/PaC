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
        [switch]$PassThru
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
        $rolePolicies = [System.Collections.Generic.List[hashtable]]::new()
        $roles = Get-PIMRoleDefinition

        foreach ($role in @($roles)) {
            if (-not $IncludeUnmodified -and -not (Test-PIMHasModifiedDate -InputObject $role)) {
                continue
            }

            try {
                $policy = Get-PIMRolePolicy -RoleDefinitionId $role.id
                if (-not $policy) {
                    continue
                }

                if (-not $IncludeUnmodified -and -not (Test-PIMHasModifiedDate -InputObject $policy)) {
                    continue
                }

                $settings = ConvertFrom-PIMPolicyToSettings -Policy $policy
                if ($settings.Count -eq 0) {
                    continue
                }

                $rolePolicies.Add(@{
                    RoleName     = $role.displayName
                    PolicySource = 'inline'
                    Settings     = $settings
                })
            }
            catch {
                Write-Warning "Failed to export role policy for '$($role.displayName)': $_"
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
        $groupPolicies = [System.Collections.Generic.List[hashtable]]::new()
        $groupsForPolicyExport = @($assignableGroups)

        if (-not $IncludeUnmodified) {
            $groupsForPolicyExport = @($groupsForPolicyExport | Where-Object { Test-PIMHasModifiedDate -InputObject $_ })
        }

        foreach ($group in $groupsForPolicyExport) {
            try {
                $policy = Get-PIMGroupPolicy -GroupId $group.id
                if (-not $policy) {
                    continue
                }

                if (-not $IncludeUnmodified -and -not (Test-PIMHasModifiedDate -InputObject $policy)) {
                    continue
                }

                $settings = ConvertFrom-PIMPolicyToSettings -Policy $policy
                if ($settings.Count -eq 0) {
                    continue
                }

                $groupPolicies.Add(@{
                    GroupName    = $group.displayName
                    GroupId      = $group.id
                    PolicySource = 'inline'
                    Settings     = $settings
                })
            }
            catch {
                Write-Warning "Failed to export group policy for '$($group.displayName)': $_"
            }
        }

        $backup['GroupPolicies'] = @($groupPolicies)
    }

    if ($IncludeRoleToGroupAssignments) {
        $roleAssignmentsByGroup = [System.Collections.Generic.List[hashtable]]::new()

        foreach ($group in $assignableGroups) {
            try {
                $filter = "principalId eq '$($group.id)' and directoryScopeId eq '/'"
                $uri = "roleManagement/directory/roleAssignments?`$filter=$([uri]::EscapeDataString($filter))"
                $assignments = @(Invoke-PIMGraphRequest -Method GET -Uri $uri -ExpandNextLink)

                if ($assignments.Count -eq 0) {
                    continue
                }

                $roleDefinitionIds = @($assignments | ForEach-Object { $_.roleDefinitionId } | Where-Object { $_ } | Select-Object -Unique)
                if ($roleDefinitionIds.Count -eq 0) {
                    continue
                }

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
                    RoleDefinitionIds = $roleDefinitionIds
                    RoleNames         = @($roleNames | Select-Object -Unique)
                })
            }
            catch {
                Write-Warning "Failed to export role-to-group assignments for '$($group.displayName)': $_"
            }
        }

        $backup['RoleToGroupAssignments'] = @($roleAssignmentsByGroup)
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
