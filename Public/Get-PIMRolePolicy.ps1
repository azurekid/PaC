function Get-PIMRolePolicy {
    <#
    .SYNOPSIS
        Retrieves the current PIM policy settings for one or more Entra ID roles.
    .DESCRIPTION
        Looks up the role management policy assigned to the specified role(s) and
        returns a simplified view of the key policy settings, suitable for
        inspection or comparison.
    .PARAMETER RoleName
        Optional. One or more Entra ID role display names (e.g. 'Security Administrator').
        If omitted, returns policy settings for all role policy assignments.
    .PARAMETER RoleDefinitionId
        Optional. One or more Entra ID role definition GUIDs. Use this instead of RoleName
        when you already have the ID.
    .PARAMETER Raw
        Returns the full Graph API policy object (including all rules) instead of
        the simplified settings view.
    .OUTPUTS
        PSCustomObject — simplified policy settings per role (or raw Graph object when -Raw).
    .EXAMPLE
        Get-PIMRolePolicy -RoleName 'Security Administrator'

    .EXAMPLE
        Get-PIMRolePolicy -RoleName 'Security Administrator', 'Privileged Role Administrator'

    .EXAMPLE
        Get-PIMRolePolicy -RoleDefinitionId '194ae4cb-b126-40b2-bd5b-6091b380977d' -Raw
    #>
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(ParameterSetName = 'ByName', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$RoleName,

        [Parameter(Mandatory, ParameterSetName = 'ById')]
        [string[]]$RoleDefinitionId,

        [Parameter()]
        [switch]$Raw
    )

    process {
        $ids = [System.Collections.Generic.List[hashtable]]::new()
        Write-Verbose "Retrieving role definitions for specified roles..."
        if ($PSCmdlet.ParameterSetName -eq 'ByName') {
            if ($RoleName -and $RoleName.Count -gt 0) {
                foreach ($name in $RoleName) {
                    $roleDef = Get-PIMRoleDefinition -DisplayName $name | Where-Object { $_.displayName -ieq $name }
                    if (-not $roleDef) {
                        Write-Warning "Role '$name' was not found."
                        continue
                    }
                    Write-Output "Found role '$($roleDef.displayName)' with ID '$($roleDef.id)'."
                    $ids.Add(@{ Id = $roleDef.id; Name = $roleDef.displayName })
                }
            }
            else {
                Write-Verbose 'No RoleName provided. Retrieving all role policy assignments.'
                $assignmentFilter = "scopeId eq '/' and scopeType eq 'DirectoryRole'"
                $assignmentUri = "policies/roleManagementPolicyAssignments?`$filter=$([uri]::EscapeDataString($assignmentFilter))&`$select=roleDefinitionId"
                $assignments = @(Invoke-PIMGraphRequest -Method GET -Uri $assignmentUri -ExpandNextLink)

                $uniqueRoleIds = @($assignments |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_.roleDefinitionId) } |
                    Select-Object -ExpandProperty roleDefinitionId -Unique)

                foreach ($id in $uniqueRoleIds) {
                    try {
                        $roleDef = Get-PIMRoleDefinition -RoleDefinitionId $id
                        $ids.Add(@{ Id = $roleDef.id; Name = $roleDef.displayName })
                    }
                    catch {
                        $ids.Add(@{ Id = $id; Name = $id })
                    }
                }
            }
        }
        else {
            foreach ($id in $RoleDefinitionId) {
                try {
                    $roleDef = Get-PIMRoleDefinition -RoleDefinitionId $id
                    Write-Verbose "Found role '$($roleDef.displayName)' with ID '$($roleDef.id)'."
                    $ids.Add(@{ Id = $roleDef.id; Name = $roleDef.displayName })
                }
                catch {
                    Write-Warning "Role definition ID '$id' was not found."
                }
            }
        }

        foreach ($role in $ids) {
            try {
                $policy = Get-PIMRoleManagementPolicy -RoleDefinitionId $role.Id

                if ($Raw) {
                    Write-Verbose "Returning raw policy for role '$($role.Name)'."
                    $policy | Add-Member -NotePropertyName 'RoleName' -NotePropertyValue $role.Name -Force
                    Write-Output $policy
                    continue
                }

                Write-Output (ConvertFrom-PIMPolicyRules -Policy $policy -RoleName $role.Name)
            }
            catch {
                Write-Warning "Could not retrieve policy for role '$($role.Name)': $_"
            }
        }
    }
}

function ConvertFrom-PIMPolicyRules {
    <#
    .SYNOPSIS
        Converts the raw Graph API policy rules into a simplified PSCustomObject.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] [string]$RoleName
    )

    $result = [ordered]@{
        RoleName                   = $RoleName
        PolicyId                   = $Policy.id
        ActivationDuration         = $null
        AllowPermanentActivation   = $null
        ActivationRequirements     = $null
        ApprovalRequired           = $null
        Approvers                  = $null
        MaximumEligibilityDuration = $null
        AllowPermanentEligibility  = $null
        Notifications              = [ordered]@{}
    }

    foreach ($rule in $Policy.rules) {
        switch ($rule.id) {
            'Expiration_EndUser_Assignment' {
                $result.AllowPermanentActivation = (-not $rule.isExpirationRequired)
                $result.ActivationDuration       = $rule.maximumDuration
            }
            'Enablement_EndUser_Assignment' {
                $result.ActivationRequirements = $rule.enabledRules -join ','
            }
            'Approval_EndUser_Assignment' {
                $result.ApprovalRequired = $rule.setting.isApprovalRequired
                $approvers = @($rule.setting.approvalStages | ForEach-Object {
                    $_.primaryApprovers
                } | Where-Object { $_ })
                $result.Approvers = $approvers
            }
            'Expiration_Admin_Eligibility' {
                $result.AllowPermanentEligibility  = (-not $rule.isExpirationRequired)
                $result.MaximumEligibilityDuration = $rule.maximumDuration
            }
            { $_ -like 'Notification_*' } {
                $result.Notifications[$rule.id] = [ordered]@{
                    notificationLevel          = $rule.notificationLevel
                    isDefaultRecipientsEnabled = $rule.isDefaultRecipientsEnabled
                    notificationRecipients     = $rule.notificationRecipients
                }
            }
        }
    }

    return [PSCustomObject]$result
}
