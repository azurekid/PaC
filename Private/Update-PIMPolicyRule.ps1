function Update-PIMPolicyRule {
    <#
    .SYNOPSIS
        Updates a single rule within a role management policy via PATCH.
    .DESCRIPTION
        Internal helper. Sends a PATCH request to update one rule of the specified
        role management policy.
    .PARAMETER PolicyId
        The ID of the roleManagementPolicy to update.
    .PARAMETER Rule
        A hashtable representing the rule body (must include 'id' and '@odata.type').
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [string]$PolicyId,

        [Parameter(Mandatory)]
        [hashtable]$Rule
    )

    $ruleId = $Rule['id']
    if (-not $ruleId) {
        throw "Rule hashtable must contain an 'id' key."
    }

    $uri = "policies/roleManagementPolicies/$PolicyId/rules/$ruleId"

    if ($PSCmdlet.ShouldProcess($uri, 'PATCH rule')) {
        Invoke-PIMGraphRequest -Method PATCH -Uri $uri -Body $Rule | Out-Null
        Write-Verbose "Updated rule '$ruleId' on policy '$PolicyId'."
    }
}
