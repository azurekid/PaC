function Set-PIMRoleGroupAssignment {
    <#
    .SYNOPSIS
        Assigns one or more Entra ID roles to a role-assignable group.
    .DESCRIPTION
        Resolves the target role definition(s) and group, checks whether each
        assignment already exists, and creates missing assignments using the
        Microsoft Graph roleAssignments endpoint.

        This enables the recommended model where privileged roles are assigned
        to a role-assignable group and users are managed through that group.
    .PARAMETER RoleName
        One or more Entra ID role display names.
    .PARAMETER RoleDefinitionId
        One or more Entra ID role definition GUIDs.
    .PARAMETER GroupName
        Display name of the role-assignable group.
    .PARAMETER GroupId
        Object ID of the role-assignable group.
    .PARAMETER PassThru
        When specified, returns created or existing assignment objects.
    .EXAMPLE
        Set-PIMRoleGroupAssignment -GroupName 'PAM-Administrators' -RoleName 'Global Reader', 'Security Administrator'
    #>
    [CmdletBinding(DefaultParameterSetName = 'RoleNameGroupName', SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, ParameterSetName = 'RoleNameGroupName')]
        [Parameter(Mandatory, ParameterSetName = 'RoleNameGroupId')]
        [string[]]$RoleName,

        [Parameter(Mandatory, ParameterSetName = 'RoleIdGroupName')]
        [Parameter(Mandatory, ParameterSetName = 'RoleIdGroupId')]
        [string[]]$RoleDefinitionId,

        [Parameter(Mandatory, ParameterSetName = 'RoleNameGroupName')]
        [Parameter(Mandatory, ParameterSetName = 'RoleIdGroupName')]
        [string]$GroupName,

        [Parameter(Mandatory, ParameterSetName = 'RoleNameGroupId')]
        [Parameter(Mandatory, ParameterSetName = 'RoleIdGroupId')]
        [string]$GroupId,

        [Parameter()]
        [switch]$PassThru
    )

    $resolvedGroupId = $GroupId
    $resolvedGroupName = $GroupName

    if (-not $resolvedGroupId) {
        $escapedName = $GroupName.Replace("'", "''")
        $groupFilter = "displayName eq '$escapedName'"
        $groupUri = "groups?`$filter=$([uri]::EscapeDataString($groupFilter))&`$select=id,displayName,isAssignableToRole"

        $groupMatch = Invoke-PIMGraphRequest -Method GET -Uri $groupUri -ExpandNextLink
        if (-not $groupMatch -or $groupMatch.Count -eq 0) {
            throw "Group '$GroupName' was not found."
        }

        $group = @($groupMatch | Where-Object { $_.displayName -eq $GroupName } | Select-Object -First 1)
        if (-not $group) {
            $group = @($groupMatch | Select-Object -First 1)
        }

        $resolvedGroupId = $group[0].id
        $resolvedGroupName = $group[0].displayName

        if ($group[0].isAssignableToRole -ne $true) {
            throw "Group '$resolvedGroupName' is not role-assignable. Create/use a group with isAssignableToRole=true."
        }
    }
    else {
        $group = Invoke-PIMGraphRequest -Method GET -Uri "groups/$resolvedGroupId?`$select=id,displayName,isAssignableToRole"
        if (-not $group) {
            throw "Group '$resolvedGroupId' was not found."
        }
        $resolvedGroupName = $group.displayName

        if ($group.isAssignableToRole -ne $true) {
            throw "Group '$resolvedGroupName' is not role-assignable. Create/use a group with isAssignableToRole=true."
        }
    }

    $roleTargets = [System.Collections.Generic.List[hashtable]]::new()

    if ($RoleName) {
        foreach ($name in $RoleName) {
            $roleDef = Get-PIMRoleDefinition -DisplayName $name | Where-Object { $_.displayName -ieq $name } | Select-Object -First 1
            if (-not $roleDef) {
                Write-Warning "Role '$name' was not found. Skipping."
                continue
            }
            $roleTargets.Add(@{ Id = $roleDef.id; Name = $roleDef.displayName })
        }
    }
    else {
        foreach ($id in $RoleDefinitionId) {
            try {
                $roleDef = Get-PIMRoleDefinition -RoleDefinitionId $id
                $roleTargets.Add(@{ Id = $roleDef.id; Name = $roleDef.displayName })
            }
            catch {
                Write-Warning "Role definition ID '$id' was not found. Skipping."
            }
        }
    }

    if ($roleTargets.Count -eq 0) {
        Write-Warning 'No valid role targets found. Nothing to assign.'
        return
    }

    $output = [System.Collections.Generic.List[object]]::new()

    foreach ($role in $roleTargets) {
        if (-not $PSCmdlet.ShouldProcess("Role '$($role.Name)'", "Assign to group '$resolvedGroupName'")) {
            continue
        }

        $assignmentFilter = "roleDefinitionId eq '$($role.Id)' and principalId eq '$resolvedGroupId' and directoryScopeId eq '/'"
        $assignmentUri = "roleManagement/directory/roleAssignments?`$filter=$([uri]::EscapeDataString($assignmentFilter))"
        $existing = Invoke-PIMGraphRequest -Method GET -Uri $assignmentUri -ExpandNextLink

        if ($existing -and $existing.Count -gt 0) {
            Write-Host "  [=] '$($role.Name)' already assigned to group '$resolvedGroupName'." -ForegroundColor DarkGray
            if ($PassThru) {
                $output.Add($existing[0])
            }
            continue
        }

        $body = @{
            roleDefinitionId = $role.Id
            principalId      = $resolvedGroupId
            directoryScopeId = '/'
        }

        $created = Invoke-PIMGraphRequest -Method POST -Uri 'roleManagement/directory/roleAssignments' -Body $body
        Write-Host "  [+] Assigned '$($role.Name)' to group '$resolvedGroupName'." -ForegroundColor Green

        if ($PassThru) {
            $output.Add($created)
        }
    }

    if ($PassThru) {
        return $output
    }
}
