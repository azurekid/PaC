function Restore-PIMConfiguration {
    <#
    .SYNOPSIS
        Restores PIM configuration from a backup configuration file.
    .DESCRIPTION
        Convenience wrapper over Invoke-PIMConfiguration so restore workflows
        are explicit and discoverable alongside Export-PIMConfiguration.
    .PARAMETER ConfigurationFile
        Path to backup JSON/YAML file created by Export-PIMConfiguration.
    .PARAMETER TemplateFile
        Optional separate templates file.
    .PARAMETER TemplateDirectory
        Optional template directory.
    .EXAMPLE
        Restore-PIMConfiguration -ConfigurationFile './backups/pim-backup.json'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$ConfigurationFile,

        [Parameter()]
        [ValidateScript({ -not $_ -or (Test-Path $_ -PathType Leaf) })]
        [string]$TemplateFile,

        [Parameter()]
        [ValidateScript({ -not $_ -or (Test-Path $_ -PathType Container) })]
        [string]$TemplateDirectory
    )

    Invoke-PIMConfiguration -ConfigurationFile $ConfigurationFile -TemplateFile $TemplateFile -TemplateDirectory $TemplateDirectory -WhatIf:$WhatIfPreference
}
