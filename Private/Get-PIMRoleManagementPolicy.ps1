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
    $policyUri = "policies/roleManagementPolicies/$policyId`?`$expand=rules"

    return Invoke-PIMGraphRequest -Method GET -Uri $policyUri
}
