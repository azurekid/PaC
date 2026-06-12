function Get-PIMRolePolicy {
    <#
    .SYNOPSIS
        Retrieves the current PIM policy settings for one or more Entra ID roles.
    .DESCRIPTION
        Looks up the role management policy assigned to the specified role(s) and
        returns a simplified view of the key policy settings, suitable for
        inspection or comparison.
    .PARAMETER RoleName
        One or more Entra ID role display names (e.g. 'Security Administrator').
    .PARAMETER RoleDefinitionId
        One or more Entra ID role definition GUIDs. Use this instead of RoleName
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
        [Parameter(Mandatory, ParameterSetName = 'ByName', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$RoleName,

        [Parameter(Mandatory, ParameterSetName = 'ById')]
        [string[]]$RoleDefinitionId,

        [Parameter()]
        [switch]$Raw
    )

    process {
        $ids = [System.Collections.Generic.List[hashtable]]::new()

        if ($PSCmdlet.ParameterSetName -eq 'ByName') {
            foreach ($name in $RoleName) {
                $roleDef = Get-PIMRoleDefinition -DisplayName $name | Where-Object { $_.displayName -ieq $name }
                if (-not $roleDef) {
                    Write-Warning "Role '$name' was not found."
                    continue
                }
                $ids.Add(@{ Id = $roleDef.id; Name = $roleDef.displayName })
            }
        }
        else {
            foreach ($id in $RoleDefinitionId) {
                try {
                    $roleDef = Get-PIMRoleDefinition -RoleDefinitionId $id
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
