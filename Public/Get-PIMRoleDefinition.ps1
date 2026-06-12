function Get-PIMRoleDefinition {
    <#
    .SYNOPSIS
        Retrieves Entra ID (Azure AD) role definitions.
    .DESCRIPTION
        Queries the Microsoft Graph API to return built-in and custom Entra ID
        role definitions. Results can be filtered by display name.
    .PARAMETER DisplayName
        Optional. Filters results to roles whose display name contains the
        specified string (case-insensitive).
    .PARAMETER RoleDefinitionId
        Optional. Returns the single role definition with the specified GUID.
    .PARAMETER All
        When specified, returns all role definitions (both enabled and disabled).
        By default, only enabled (isEnabled -eq $true) roles are returned.
    .OUTPUTS
        PSCustomObject — one or more roleDefinition objects.
    .EXAMPLE
        # List all enabled role definitions
        Get-PIMRoleDefinition

    .EXAMPLE
        # Filter by name
        Get-PIMRoleDefinition -DisplayName 'Security Administrator'

    .EXAMPLE
        # Get a specific role by ID
        Get-PIMRoleDefinition -RoleDefinitionId '194ae4cb-b126-40b2-bd5b-6091b380977d'
    #>
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(ParameterSetName = 'ByName')]
        [string]$DisplayName,

        [Parameter(Mandatory, ParameterSetName = 'ById')]
        [string]$RoleDefinitionId,

        [Parameter(ParameterSetName = 'ByName')]
        [switch]$All
    )

    if ($PSCmdlet.ParameterSetName -eq 'ById') {
        return Invoke-PIMGraphRequest -Method GET -Uri "roleManagement/directory/roleDefinitions/$RoleDefinitionId"
    }

    $roles = Invoke-PIMGraphRequest -Method GET -Uri 'roleManagement/directory/roleDefinitions' -ExpandNextLink

    if (-not $All) {
        $roles = $roles | Where-Object { $_.isEnabled -eq $true }
    }

    if ($DisplayName) {
        $roles = $roles | Where-Object { $_.displayName -like "*$DisplayName*" }
    }

    return $roles
}
