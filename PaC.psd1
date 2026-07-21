@{
    ModuleVersion     = '0.1.0'
    GUID              = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author            = 'Rogier Dijkman'
    CompanyName       = ''
    Copyright         = '(c) 2026 Rogier Dijkman. MIT License.'
    Description       = 'PaC (PIM as Code): PowerShell module for managing Microsoft Privileged Identity Management (PIM) at scale using Microsoft Graph API. Supports JSON and YAML configuration files with reusable policy templates.'
    PowerShellVersion = '7.0'
    RootModule        = 'PaC.psm1'

    FunctionsToExport = @(
        'Connect-PIM'
        'Disconnect-PIM'
        'Get-PIMRoleDefinition'
        'Get-PIMRolePolicy'
        'Get-PIMGroupPolicy'
        'Export-PIMConfiguration'
        'Restore-PIMConfiguration'
        'Set-PIMRolePolicy'
        'Set-PIMGroupPolicy'
        'Set-PIMRoleGroupAssignment'
        'Invoke-PIMConfiguration'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('PaC', 'PIM', 'Azure', 'EntraID', 'AzureAD', 'Graph', 'Security', 'Identity', 'Governance')
            LicenseUri   = 'https://github.com/azurekid/PaC/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/azurekid/PaC'
            ReleaseNotes = 'Initial release of PaC (PIM as Code): PowerShell module for managing PIM policies at scale using Microsoft Graph API with support for policy templates and JSON/YAML configuration files.'
        }
    }
}
