function Get-PIMGroupPolicy {
    <#
    .SYNOPSIS
        Retrieves current PIM for Groups policy settings for one or more groups.
    .DESCRIPTION
        Resolves a group by name or ID, retrieves the attached role management policy,
        and returns either the raw policy object or a simplified settings view.
    .PARAMETER GroupName
        Optional. One or more Microsoft Entra group display names.
        If omitted, returns member policies for all groups with a PIM policy assignment.
    .PARAMETER GroupId
        Optional. One or more Microsoft Entra group object IDs.
    .PARAMETER Raw
        When specified, returns the raw policy object including rules.
    #>
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(ParameterSetName = 'ByName', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$GroupName,

        [Parameter(Mandatory, ParameterSetName = 'ById')]
        [string[]]$GroupId,

        [Parameter()]
        [switch]$Raw
    )

    process {
        $groups = [System.Collections.Generic.List[hashtable]]::new()

        if ($PSCmdlet.ParameterSetName -eq 'ByName') {
            if ($GroupName -and $GroupName.Count -gt 0) {
                foreach ($name in $GroupName) {
                    $escapedName = $name.Replace("'", "''")
                    $groupFilter = "displayName eq '$escapedName'"
                    $uri = "groups?`$filter=$([uri]::EscapeDataString($groupFilter))&`$select=id,displayName"
                    $match = Invoke-PIMGraphRequest -Method GET -Uri $uri -ExpandNextLink

                    if (-not $match -or $match.Count -eq 0) {
                        Write-Warning "Group '$name' was not found."
                        continue
                    }

                    $exact = @($match | Where-Object { $_.displayName -eq $name } | Select-Object -First 1)
                    if (-not $exact) {
                        $exact = @($match | Select-Object -First 1)
                    }

                    $groups.Add(@{ Id = $exact[0].id; Name = $exact[0].displayName })
                }
            }
            else {
                Write-Verbose 'No GroupName provided. Retrieving all group member policy assignments.'
                $assignmentFilter = "scopeType eq 'Group' and roleDefinitionId eq 'member'"
                $assignmentUri = "policies/roleManagementPolicyAssignments?`$filter=$([uri]::EscapeDataString($assignmentFilter))&`$select=scopeId,roleDefinitionId,policyId"
                $assignments = @(Invoke-PIMGraphRequest -Method GET -Uri $assignmentUri -ExpandNextLink)

                $uniqueGroupIds = @($assignments |
                    ForEach-Object {
                        $scopeId = [string]$_.scopeId
                        if ([string]::IsNullOrWhiteSpace($scopeId)) {
                            return
                        }

                        if ($scopeId -match '^/groups/(?<id>[0-9a-fA-F-]{36})$') {
                            return $matches.id
                        }

                        if ($scopeId -match '^(?<id>[0-9a-fA-F-]{36})$') { return $matches.id }
                    } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                    Select-Object -Unique)

                foreach ($id in $uniqueGroupIds) {
                    try {
                        $group = Invoke-PIMGraphRequest -Method GET -Uri "groups/$id?`$select=id,displayName"
                        $groups.Add(@{ Id = $group.id; Name = $group.displayName })
                    }
                    catch {
                        $groups.Add(@{ Id = $id; Name = $id })
                    }
                }
            }
        }
        else {
            foreach ($id in $GroupId) {
                try {
                    $group = Invoke-PIMGraphRequest -Method GET -Uri "groups/$id?`$select=id,displayName"
                    $groups.Add(@{ Id = $group.id; Name = $group.displayName })
                }
                catch {
                    Write-Warning "Group ID '$id' was not found."
                }
            }
        }

        foreach ($group in $groups) {
            try {
                $policy = Get-PIMGroupManagementPolicy -GroupId $group.Id

                if ($Raw) {
                    $policy | Add-Member -NotePropertyName 'GroupName' -NotePropertyValue $group.Name -Force
                    $policy | Add-Member -NotePropertyName 'GroupId' -NotePropertyValue $group.Id -Force
                    Write-Output $policy
                    continue
                }

                $result = [ordered]@{
                    GroupName                  = $group.Name
                    GroupId                    = $group.Id
                    PolicyId                   = $policy.id
                    ActivationDuration         = $null
                    AllowPermanentActivation   = $null
                    ActivationRequirements     = $null
                    ApprovalRequired           = $null
                    Approvers                  = $null
                    MaximumEligibilityDuration = $null
                    AllowPermanentEligibility  = $null
                    Notifications              = [ordered]@{}
                }

                foreach ($rule in $policy.rules) {
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

                Write-Output ([PSCustomObject]$result)
            }
            catch {
                Write-Warning "Could not retrieve group policy for '$($group.Name)': $_"
            }
        }
    }
}
