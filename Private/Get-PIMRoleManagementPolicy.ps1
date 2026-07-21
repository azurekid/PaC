function Get-PIMRoleManagementPolicy {
    <#
    .SYNOPSIS
        Retrieves the role management policy assigned to a given Entra ID role definition.
    .DESCRIPTION
        Internal helper. Looks up the roleManagementPolicyAssignment for the specified
        role definition ID, then retrieves the full policy (including expanded rules).
    .PARAMETER RoleDefinitionId
        The GUID of the Entra ID role definition.
    .OUTPUTS
        PSCustomObject — the roleManagementPolicy object with Rules expanded.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory)]
        [string]$RoleDefinitionId
    )

    $filter = "scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$RoleDefinitionId'"
    $assignmentUri = "policies/roleManagementPolicyAssignments?`$filter=$filter"

    $assignment = Invoke-PIMGraphRequest -Method GET -Uri $assignmentUri -ExpandNextLink

    if (-not $assignment -or $assignment.Count -eq 0) {
        throw "No role management policy assignment found for role definition ID '$RoleDefinitionId'."
    }

    $policyId  = $assignment[0].policyId
    $assignmentId = $assignment | Where-Object { -not [string]::IsNullOrWhiteSpace($_.id) } | Select-Object -First 1 -ExpandProperty id
    $policyUri = "policies/roleManagementPolicies/$policyId"


    # Fetch policy metadata first (stable), then fetch rules using multiple strategies.
    # Some tenants intermittently return 500 or empty rules for one approach.
    $policy = Invoke-PIMGraphRequest -Method GET -Uri $policyUri

    $rules = @()
    $effectiveRules = @()

    # Strategy 1: Expanded policy endpoint
    $expandedPolicyUri = '{0}?$expand=rules,effectiveRules' -f $policyUri
    try {
        $expanded = Invoke-PIMGraphRequest -Method GET -Uri $expandedPolicyUri
        if ($expanded -and $null -ne $expanded.rules) {
            $rules = @($expanded.rules | Where-Object { $null -ne $_ })
        }
        if ($expanded -and $null -ne $expanded.effectiveRules) {
            $effectiveRules = @($expanded.effectiveRules | Where-Object { $null -ne $_ })
        }
    }
    catch { }

    # Strategy 2: Direct rules collection
    if ($rules.Count -eq 0) {
        $rulesUri = '{0}/rules' -f $policyUri
        try {
            $collection = Invoke-PIMGraphRequest -Method GET -Uri $rulesUri -ExpandNextLink
            if ($collection) {
                $rules = @($collection | Where-Object { $null -ne $_ })
            }
        }
        catch { }
    }

    # Strategy 3: Expand through assignment by id (tenant-specific fallback)
    if ($rules.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($assignmentId)) {
        $assignmentExpandUri = 'policies/roleManagementPolicyAssignments/{0}?`$expand=policy(`$expand=rules,effectiveRules)' -f $assignmentId
        try {
            $assignmentExpanded = Invoke-PIMGraphRequest -Method GET -Uri $assignmentExpandUri
            if ($assignmentExpanded -and $assignmentExpanded.policy -and $null -ne $assignmentExpanded.policy.rules) {
                $rules = @($assignmentExpanded.policy.rules | Where-Object { $null -ne $_ })
            }
            if ($effectiveRules.Count -eq 0 -and $assignmentExpanded -and $assignmentExpanded.policy -and $null -ne $assignmentExpanded.policy.effectiveRules) {
                $effectiveRules = @($assignmentExpanded.policy.effectiveRules | Where-Object { $null -ne $_ })
            }
        }
        catch { }
    }

    # Strategy 4: Expand through assignment collection with filter (works in some tenants where by-id endpoint fails)
    if ($rules.Count -eq 0) {
        $assignmentExpandedCollectionUri = "policies/roleManagementPolicyAssignments?`$filter=$filter&`$expand=policy(`$expand=rules,effectiveRules)"
        try {
            $assignmentCollection = Invoke-PIMGraphRequest -Method GET -Uri $assignmentExpandedCollectionUri -ExpandNextLink
            $assignmentWithPolicy = @($assignmentCollection | Where-Object { $_.policy -and $_.policy.id -eq $policyId } | Select-Object -First 1)
            if (-not $assignmentWithPolicy) {
                $assignmentWithPolicy = @($assignmentCollection | Where-Object { $_.policy } | Select-Object -First 1)
            }

            if ($assignmentWithPolicy -and $assignmentWithPolicy[0].policy -and $null -ne $assignmentWithPolicy[0].policy.rules) {
                $rules = @($assignmentWithPolicy[0].policy.rules | Where-Object { $null -ne $_ })
            }
            if ($effectiveRules.Count -eq 0 -and $assignmentWithPolicy -and $assignmentWithPolicy[0].policy -and $null -ne $assignmentWithPolicy[0].policy.effectiveRules) {
                $effectiveRules = @($assignmentWithPolicy[0].policy.effectiveRules | Where-Object { $null -ne $_ })
            }
        }
        catch { }
    }

    if ($rules.Count -eq 0 -and $effectiveRules.Count -gt 0) {
        $rules = $effectiveRules
    }

    # Strategy 5: Retrieve known rule IDs one-by-one (v1.0 first, beta fallback).
    # Some tenants return 500 for collection/expand endpoints but allow direct rule id reads.
    if ($rules.Count -eq 0) {
        $knownRuleIds = @(
            'Expiration_EndUser_Assignment'
            'Enablement_EndUser_Assignment'
            'Approval_EndUser_Assignment'
            'Expiration_Admin_Eligibility'
            'Expiration_Admin_Assignment'
            'Enablement_Admin_Assignment'
            'Notification_Requestor_EndUser_Assignment'
            'Notification_Admin_EndUser_Assignment'
            'Notification_Admin_Admin_Eligibility'
            'Notification_Requestor_Admin_Assignment'
            'Notification_Admin_Admin_Assignment'
        )

        $retrievedRules = [System.Collections.Generic.List[object]]::new()

        foreach ($ruleId in $knownRuleIds) {
            $ruleObject = $null

            try {
                $v1RuleUri = "https://graph.microsoft.com/v1.0/$policyUri/rules/$ruleId"
                $ruleObject = Invoke-PIMGraphRequest -Method GET -Uri $v1RuleUri
            }
            catch { }

            if (-not $ruleObject) {
                try {
                    $betaRuleUri = "https://graph.microsoft.com/beta/$policyUri/rules/$ruleId"
                    $ruleObject = Invoke-PIMGraphRequest -Method GET -Uri $betaRuleUri
                }
                catch { }
            }

            if ($ruleObject -and $ruleObject.id -eq $ruleId) {
                $retrievedRules.Add($ruleObject)
            }
        }

        if ($retrievedRules.Count -gt 0) {
            $rules = @($retrievedRules)
        }
    }

    if ($rules.Count -eq 0) {
        Write-Warning "Policy '$policyId' returned 0 rules from all retrieval strategies. Falling back to apply-all mode."
    }

    $policy | Add-Member -NotePropertyName 'rules' -NotePropertyValue $rules -Force

    return $policy
}
