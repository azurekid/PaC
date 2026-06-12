function Invoke-PIMConfiguration {
    <#
    .SYNOPSIS
        Applies PIM policy configuration from a JSON or YAML file.
    .DESCRIPTION
        Reads a configuration file that defines policy templates and/or role-specific
        settings, then applies them to the corresponding Entra ID role management
        policies via the Microsoft Graph API.

        Configuration file format (JSON or YAML):

          PolicyTemplates  - Named template blocks containing reusable settings.
          EntraRoles       - Contains a 'Policies' array of per-role configurations.

        Each entry in EntraRoles.Policies can specify:
          RoleName      - Display name of the Entra ID role (required).
          PolicySource  - 'template' or 'inline' (default: 'inline').
          Template      - Template name to use (required when PolicySource = 'template').
          Override      - Hashtable of settings that override the template values.
          Settings      - Inline settings block (required when PolicySource = 'inline').

        When using -TemplateDirectory, each file in the directory is loaded as a named
        template. The template name is derived from the filename (without extension).
        Each file should contain only the settings object for that template.

        YAML support requires the 'powershell-yaml' module to be installed.
    .PARAMETER ConfigurationFile
        Path to the JSON or YAML configuration file. Three formats are supported:
          1. Full config with EntraRoles.Policies array (and optional PolicyTemplates section).
          2. Single role entry — a bare object with a top-level 'RoleName' key.
          3. Legacy: an EntraRoles section without a Policies array key.
        YAML support requires the 'powershell-yaml' module to be installed.
    .PARAMETER TemplateFile
        Optional path to a separate JSON or YAML file containing PolicyTemplates.
        If templates are also defined in ConfigurationFile, the TemplateFile takes
        precedence for shared template names.
    .PARAMETER TemplateDirectory
        Optional path to a directory of individual template files. Each file is loaded
        as a named template using the filename (without extension) as the template name.
        Templates from this directory take precedence over those in ConfigurationFile
        or TemplateFile for shared template names.
    .EXAMPLE
        # Apply a single role config using templates from a directory
        Invoke-PIMConfiguration -ConfigurationFile '.\EntraRoles\Security-Administrator.json' `
                                -TemplateDirectory '.\Templates'

    .EXAMPLE
        # Use a separate templates file
        Invoke-PIMConfiguration -ConfigurationFile '.\roles.json' `
                                -TemplateFile '.\templates.json'

    .EXAMPLE
        # Preview changes without applying them
        Invoke-PIMConfiguration -ConfigurationFile '.\EntraRoles\Security-Administrator.json' `
                                -TemplateDirectory '.\Templates' -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
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

    #region Load configuration file
    $config = Import-PIMConfigFile -Path $ConfigurationFile
    #endregion

    #region Load templates
    $templates = @{}

    if ($config.PolicyTemplates) {
        $rawTemplates = if ($config.PolicyTemplates -is [hashtable]) {
            $config.PolicyTemplates
        }
        else {
            ConvertTo-Hashtable -InputObject $config.PolicyTemplates
        }

        foreach ($name in $rawTemplates.Keys) {
            $t = $rawTemplates[$name]
            $templates[$name] = if ($t -is [hashtable]) { $t } else { ConvertTo-Hashtable -InputObject $t }
        }
    }

    if ($TemplateFile) {
        $templateConfig = Import-PIMConfigFile -Path $TemplateFile
        if ($templateConfig.PolicyTemplates) {
            $rawOverrideTemplates = if ($templateConfig.PolicyTemplates -is [hashtable]) {
                $templateConfig.PolicyTemplates
            }
            else {
                ConvertTo-Hashtable -InputObject $templateConfig.PolicyTemplates
            }

            foreach ($name in $rawOverrideTemplates.Keys) {
                $t = $rawOverrideTemplates[$name]
                $templates[$name] = if ($t -is [hashtable]) { $t } else { ConvertTo-Hashtable -InputObject $t }
            }
        }
    }

    if ($TemplateDirectory) {
        $templateFiles = Get-ChildItem -Path $TemplateDirectory -File |
            Where-Object { $_.Extension -in @('.json', '.yml', '.yaml') }

        foreach ($file in $templateFiles) {
            $templateName    = $file.BaseName
            $templateContent = Import-PIMConfigFile -Path $file.FullName
            $templates[$templateName] = if ($templateContent -is [hashtable]) {
                $templateContent
            }
            else {
                ConvertTo-Hashtable -InputObject $templateContent
            }
        }
    }
    #endregion

    #region Resolve policies list
    # Support single-entry config files (a bare role object) as well as the full
    # EntraRoles.Policies array format.
    $policies = $null

    if ($config.EntraRoles) {
        $entraRoles = $config.EntraRoles
        $policies   = $entraRoles.Policies ?? $entraRoles['Policies']
    }
    elseif ($config.RoleName) {
        # Single role entry — wrap it so the loop below works uniformly.
        $policies = @($config)
    }

    if (-not $policies) {
        Write-Warning "No 'EntraRoles' section or top-level 'RoleName' found in the configuration file. Nothing to process."
        return
    }

    $successCount = 0
    $failureCount = 0

    foreach ($rawPolicy in $policies) {
        $policyConfig = if ($rawPolicy -is [hashtable]) { $rawPolicy } else { ConvertTo-Hashtable -InputObject $rawPolicy }
        $roleName     = $policyConfig['RoleName']

        if (-not $roleName) {
            Write-Warning "Policy entry is missing 'RoleName'. Skipping."
            $failureCount++
            continue
        }

        try {
            $settings = Resolve-PIMTemplate -PolicyConfig $policyConfig -Templates $templates
            Write-Verbose "Resolved settings for role '$roleName'."

            if ($PSCmdlet.ShouldProcess("Role '$roleName'", 'Apply PIM policy')) {
                Set-PIMRolePolicy -RoleName $roleName -Settings $settings
                $successCount++
            }
        }
        catch {
            Write-Error "Failed to process policy for role '$roleName': $_"
            $failureCount++
        }
    }

    Write-Host "`nConfiguration complete. Succeeded: $successCount | Failed: $failureCount" -ForegroundColor $(
        if ($failureCount -gt 0) { 'Yellow' } else { 'Green' }
    )
    #endregion
}

function Import-PIMConfigFile {
    <#
    .SYNOPSIS
        Reads a JSON or YAML configuration file and returns a PSCustomObject.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )

    $extension = [System.IO.Path]::GetExtension($Path).ToLower()
    $content   = Get-Content -Path $Path -Raw -ErrorAction Stop

    switch ($extension) {
        { $_ -in @('.json') } {
            try {
                return $content | ConvertFrom-Json -Depth 20 -ErrorAction Stop
            }
            catch {
                throw "Failed to parse JSON file '$Path': $_"
            }
        }
        { $_ -in @('.yml', '.yaml') } {
            if (-not (Get-Module -ListAvailable -Name 'powershell-yaml')) {
                throw "YAML files require the 'powershell-yaml' module. Install it with: Install-Module powershell-yaml -Scope CurrentUser"
            }
            Import-Module 'powershell-yaml' -ErrorAction Stop
            try {
                return $content | ConvertFrom-Yaml -ErrorAction Stop | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
            }
            catch {
                throw "Failed to parse YAML file '$Path': $_"
            }
        }
        default {
            throw "Unsupported file extension '$extension'. Use .json, .yml, or .yaml."
        }
    }
}
