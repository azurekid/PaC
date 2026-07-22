function Get-PIMGroupManagementPolicy {
    <#
    .SYNOPSIS
        Retrieves the PIM role management policy assigned to a group.
    .DESCRIPTION
        Internal helper for PIM for Groups. Looks up the roleManagementPolicyAssignment
        for scopeType Group and the given group ID, then retrieves the policy and rules.
    .PARAMETER GroupId
        Object ID of the Microsoft Entra group.
    .PARAMETER MemberType
        Group assignment type to target: member or owner.
    .OUTPUTS
        PSCustomObject.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory)]
        [string]$GroupId,

        [Parameter()]
        [ValidateSet('member', 'owner')]
        [string]$MemberType = 'member'
    )

    $assignmentCandidates = @(
        "scopeId eq '$GroupId' and scopeType eq 'Group' and roleDefinitionId eq '$MemberType'"
        "scopeId eq '/$GroupId' and scopeType eq 'Group' and roleDefinitionId eq '$MemberType'"
        "scopeId eq '/groups/$GroupId' and scopeType eq 'Group' and roleDefinitionId eq '$MemberType'"
        "scopeId eq '$GroupId' and scopeType eq 'Group'"
        "scopeId eq '/$GroupId' and scopeType eq 'Group'"
        "scopeId eq '/groups/$GroupId' and scopeType eq 'Group'"
    )

    $assignment = @()
    foreach ($candidateFilter in $assignmentCandidates) {
        try {
            $assignmentUri = "policies/roleManagementPolicyAssignments?`$filter=$([uri]::EscapeDataString($candidateFilter))"
            $candidate = @(Invoke-PIMGraphRequest -Method GET -Uri $assignmentUri -ExpandNextLink)
            if ($candidate.Count -gt 0) {
                $assignment = @($candidate)
                break
            }
        }
        catch {
            Write-Verbose "Group assignment lookup candidate failed; trying next scope format. Filter='$candidateFilter'. Error=$($_.Exception.Message)"
        }
    }

    if (-not $assignment -or $assignment.Count -eq 0) {
        throw "No group role management policy assignment found for group '$GroupId'."
    }

    $assignment = @($assignment | Where-Object {
        $roleDefinitionId = [string]$_.roleDefinitionId
        -not [string]::IsNullOrWhiteSpace($roleDefinitionId) -and $roleDefinitionId.Equals($MemberType, [System.StringComparison]::OrdinalIgnoreCase)
    })

    if (-not $assignment -or $assignment.Count -eq 0) {
        throw "No group role management policy assignment found for group '$GroupId' and MemberType '$MemberType'."
    }

    $policyId  = $assignment[0].policyId
    $policyUri = "policies/roleManagementPolicies/$policyId"

    $policy = Invoke-PIMGraphRequest -Method GET -Uri $policyUri

    $rules = @()
    $effectiveRules = @()

    try {
        $expandedPolicyUri = '{0}?$expand=rules,effectiveRules' -f $policyUri
        $expanded = Invoke-PIMGraphRequest -Method GET -Uri $expandedPolicyUri

        if ($expanded -and $null -ne $expanded.rules) {
            $rules = @($expanded.rules | Where-Object { $null -ne $_ })
        }
        if ($expanded -and $null -ne $expanded.effectiveRules) {
            $effectiveRules = @($expanded.effectiveRules | Where-Object { $null -ne $_ })
        }
    }
    catch { }

    if ($rules.Count -eq 0) {
        try {
            $rulesUri = '{0}/rules' -f $policyUri
            $collection = Invoke-PIMGraphRequest -Method GET -Uri $rulesUri -ExpandNextLink
            if ($collection) {
                $rules = @($collection | Where-Object { $null -ne $_ })
            }
        }
        catch { }
    }

    if ($rules.Count -eq 0 -and $effectiveRules.Count -gt 0) {
        $rules = $effectiveRules
    }

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
        Write-Warning "Group policy '$policyId' returned 0 rules from all retrieval strategies."
    }

    $policy | Add-Member -NotePropertyName 'rules' -NotePropertyValue $rules -Force
    return $policy
}
