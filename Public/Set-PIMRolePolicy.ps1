function Set-PIMRolePolicy {
    <#
    .SYNOPSIS
        Applies PIM policy settings to one or more Entra ID roles.
    .DESCRIPTION
        Converts the provided settings hashtable into Microsoft Graph API rule
        objects and patches each rule on the role's management policy.

        Supported settings keys:
          ActivationDuration            - ISO 8601 duration string (e.g. "PT4H")
          AllowPermanentActivation      - Boolean
          ActivationRequirement         - Comma-separated string or array
                                          (MultiFactorAuthentication, Justification, Ticketing)
          ApprovalRequired              - Boolean
          Approvers                     - Array of @{id; description; [type]}
          AllowPermanentEligibility     - Boolean
          MaximumEligibilityDuration    - ISO 8601 duration string (e.g. "P30D")
          Notification_Activation_Alert - Notification block hashtable
          (and other Notification_* keys — see ConvertTo-PIMPolicyRules for full list)
    .PARAMETER RoleName
        One or more Entra ID role display names.
    .PARAMETER RoleDefinitionId
        One or more Entra ID role definition GUIDs.
    .PARAMETER Settings
        A hashtable of policy settings to apply.
    .PARAMETER PassThru
        When specified, returns the updated simplified policy object for each role.
    .EXAMPLE
        Set-PIMRolePolicy -RoleName 'Security Administrator' -Settings @{
            ActivationDuration    = 'PT4H'
            ActivationRequirement = 'MultiFactorAuthentication,Justification'
            ApprovalRequired      = $false
            AllowPermanentEligibility = $false
            MaximumEligibilityDuration = 'P180D'
        }
    .EXAMPLE
        # Use -WhatIf to preview changes without applying them
        Set-PIMRolePolicy -RoleName 'Global Administrator' -Settings @{ApprovalRequired = $true} -WhatIf
    #>
    [CmdletBinding(DefaultParameterSetName = 'ByName', SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, ParameterSetName = 'ByName', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$RoleName,

        [Parameter(Mandatory, ParameterSetName = 'ById')]
        [string[]]$RoleDefinitionId,

        [Parameter(Mandatory)]
        [hashtable]$Settings,

        [Parameter()]
        [switch]$PassThru
    )

    process {
        $roleTargets = [System.Collections.Generic.List[hashtable]]::new()

        if ($PSCmdlet.ParameterSetName -eq 'ByName') {
            foreach ($name in $RoleName) {
                $roleDef = Get-PIMRoleDefinition -DisplayName $name | Where-Object { $_.displayName -ieq $name }
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

        $rules = ConvertTo-PIMPolicyRules -Settings $Settings

        if ($rules.Count -eq 0) {
            Write-Warning "No policy rules were generated from the provided settings. Nothing to apply."
            return
        }

        foreach ($role in $roleTargets) {
            if (-not $PSCmdlet.ShouldProcess("Role '$($role.Name)'", 'Apply PIM policy settings')) {
                continue
            }

            try {
                Write-Verbose "Retrieving policy for role '$($role.Name)'..."
                $policy = Get-PIMRoleManagementPolicy -RoleDefinitionId $role.Id

                foreach ($rule in $rules) {
                    Write-Verbose "Patching rule '$($rule['id'])' on policy '$($policy.id)'..."
                    Update-PIMPolicyRule -PolicyId $policy.id -Rule $rule
                }

                Write-Host "Policy applied to role '$($role.Name)'." -ForegroundColor Green

                if ($PassThru) {
                    Get-PIMRolePolicy -RoleDefinitionId $role.Id
                }
            }
            catch {
                Write-Error "Failed to apply policy to role '$($role.Name)': $_"
            }
        }
    }
}
