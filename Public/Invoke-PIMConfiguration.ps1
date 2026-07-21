function Invoke-PIMConfiguration {
    <#
    .SYNOPSIS
        Applies PIM policy configuration from a JSON or YAML file.
    .DESCRIPTION
        Reads a configuration file that defines policy templates and/or role-specific
        settings, then applies them to the corresponding Entra ID role management
        policies via the Microsoft Graph API.

                Configuration file format (JSON or YAML):

                    PolicyTemplates         - Named template blocks containing reusable settings.
                    EntraRoles              - Contains a 'Policies' array of per-role configurations.
                    GroupPolicies / EntraGroups.Policies
                                                                 - Optional array of per-group PIM policy configurations.
                    RoleToGroupAssignments  - Optional array assigning Entra roles to role-assignable groups.

        Each entry in EntraRoles.Policies can specify:
          RoleName      - Display name of the Entra ID role (required).
          PolicySource  - 'template' or 'inline' (default: 'inline').
          Template      - Template name to use (required when PolicySource = 'template').
          Override      - Hashtable of settings that override the template values.
          Settings      - Inline settings block (required when PolicySource = 'inline').

                Each entry in GroupPolicies / EntraGroups.Policies can specify:
                    GroupName     - Display name of the group (required unless GroupId is used).
                    GroupId       - Object ID of the group (required unless GroupName is used).
                                        MemberType    - 'member', 'owner', or 'both' for top-level settings entries.
                    PolicySource  - 'template' or 'inline' (default: 'inline').
                    Template      - Template name to use (required when PolicySource = 'template').
                    Override      - Hashtable of settings that override template values.
                    Settings      - Inline settings block (required when PolicySource = 'inline').
                                        Member / Owner
                                                                    - Optional per-assignment policy blocks. Each block supports
                                                                        PolicySource, Template, Override, and Settings.

                Each entry in RoleToGroupAssignments can specify:
                    GroupName         - Display name of the role-assignable group.
                    GroupId           - Object ID of the role-assignable group.
                    RoleName          - Single Entra role display name.
                    RoleNames         - Array of Entra role display names.
                    RoleDefinitionId  - Single Entra role definition ID.
                    RoleDefinitionIds - Array of Entra role definition IDs.

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
    $groupPolicies = $null

    if ($config.EntraRoles) {
        $entraRoles = $config.EntraRoles
        $policies   = $entraRoles.Policies ?? $entraRoles['Policies']
    }
    elseif ($config.RoleName) {
        # Single role entry — wrap it so the loop below works uniformly.
        $policies = @($config)
    }

    if ($config.EntraGroups) {
        $entraGroups = if ($config.EntraGroups -is [hashtable]) { $config.EntraGroups } else { ConvertTo-Hashtable -InputObject $config.EntraGroups }
        $groupPolicies = $entraGroups['Policies']
    }
    elseif ($config.GroupPolicies) {
        $groupPolicies = @($config.GroupPolicies)
    }
    elseif ($config.Groups) {
        $groupsSection = if ($config.Groups -is [hashtable]) { $config.Groups } else { ConvertTo-Hashtable -InputObject $config.Groups }
        if ($groupsSection['Policies']) {
            $groupPolicies = @($groupsSection['Policies'])
        }
    }
    elseif ($config.GroupName -or $config.GroupId) {
        # Single group policy entry.
        $groupPolicies = @($config)
    }

    $hasTopLevelGroupAssignments = $false
    if ($config.RoleToGroupAssignments) {
        $hasTopLevelGroupAssignments = @($config.RoleToGroupAssignments).Count -gt 0
    }

    $hasEntraGroupAssignments = $false
    if ($config.EntraRoles) {
        $entraRolesForAssignments = if ($config.EntraRoles -is [hashtable]) { $config.EntraRoles } else { ConvertTo-Hashtable -InputObject $config.EntraRoles }
        if ($entraRolesForAssignments['RoleToGroupAssignments']) {
            $hasEntraGroupAssignments = @($entraRolesForAssignments['RoleToGroupAssignments']).Count -gt 0
        }
        if (-not $hasEntraGroupAssignments -and $entraRolesForAssignments['GroupAssignments']) {
            $hasEntraGroupAssignments = @($entraRolesForAssignments['GroupAssignments']).Count -gt 0
        }
    }

    $hasGroupPolicies = @($groupPolicies).Count -gt 0

    if (-not $policies -and -not $hasGroupPolicies -and -not $hasTopLevelGroupAssignments -and -not $hasEntraGroupAssignments) {
        Write-Warning "No role policies, group policies, or role-to-group assignments found in the configuration file. Nothing to process."
        return
    }
        #region Phase 1 — resolve all templates sequentially
        $successCount = 0
        $failureCount = 0
        $preparedWork = [System.Collections.Generic.List[hashtable]]::new()
        $preparedGroupWork = [System.Collections.Generic.List[hashtable]]::new()

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
                $preparedWork.Add(@{ RoleName = $roleName; Settings = $settings })
            }
            catch {
                Write-Error "Failed to resolve template for role '$roleName': $_"
                $failureCount++
            }
        }

        foreach ($rawGroupPolicy in $groupPolicies) {
            $groupPolicyConfig = if ($rawGroupPolicy -is [hashtable]) { $rawGroupPolicy } else { ConvertTo-Hashtable -InputObject $rawGroupPolicy }
            $groupName = $groupPolicyConfig['GroupName']
            $groupId   = $groupPolicyConfig['GroupId']

            if (-not $groupName -and -not $groupId) {
                Write-Warning "Group policy entry is missing 'GroupName' or 'GroupId'. Skipping."
                $failureCount++
                continue
            }

            $groupTargetLabel = $groupName
            if (-not $groupTargetLabel) {
                $groupTargetLabel = $groupId
            }

            $memberTypeRaw = [string]($groupPolicyConfig['MemberType'] ?? '')
            $memberType = $memberTypeRaw.ToLower()
            if (-not $memberType) {
                $memberType = 'member'
            }

            $memberSettingsConfig = $groupPolicyConfig['Member']
            if (-not $memberSettingsConfig) { $memberSettingsConfig = $groupPolicyConfig['MemberRoleSettings'] }
            if (-not $memberSettingsConfig) { $memberSettingsConfig = $groupPolicyConfig['MemberSettings'] }

            $ownerSettingsConfig = $groupPolicyConfig['Owner']
            if (-not $ownerSettingsConfig) { $ownerSettingsConfig = $groupPolicyConfig['OwnerRoleSettings'] }
            if (-not $ownerSettingsConfig) { $ownerSettingsConfig = $groupPolicyConfig['OwnerSettings'] }

            $roleSettingsConfig = $groupPolicyConfig['RoleSettings']
            if ($roleSettingsConfig) {
                $roleSettingsTable = if ($roleSettingsConfig -is [hashtable]) { $roleSettingsConfig } else { ConvertTo-Hashtable -InputObject $roleSettingsConfig }
                if (-not $memberSettingsConfig -and $roleSettingsTable.ContainsKey('Member')) {
                    $memberSettingsConfig = $roleSettingsTable['Member']
                }
                if (-not $ownerSettingsConfig -and $roleSettingsTable.ContainsKey('Owner')) {
                    $ownerSettingsConfig = $roleSettingsTable['Owner']
                }
            }

            $hasPerAssignmentSettings = $null -ne $memberSettingsConfig -or $null -ne $ownerSettingsConfig

            if ($hasPerAssignmentSettings) {
                if ($memberSettingsConfig) {
                    try {
                        $memberPolicyConfig = if ($memberSettingsConfig -is [hashtable]) { $memberSettingsConfig } else { ConvertTo-Hashtable -InputObject $memberSettingsConfig }
                        if (-not $memberPolicyConfig.ContainsKey('PolicySource') -and -not $memberPolicyConfig.ContainsKey('Settings') -and -not $memberPolicyConfig.ContainsKey('Template')) {
                            $memberPolicyConfig = @{ PolicySource = 'inline'; Settings = $memberPolicyConfig }
                        }

                        $memberSettings = Resolve-PIMTemplate -PolicyConfig $memberPolicyConfig -Templates $templates
                        $preparedGroupWork.Add(@{ GroupName = $groupName; GroupId = $groupId; MemberType = 'member'; Settings = $memberSettings })
                    }
                    catch {
                        Write-Error "Failed to resolve member settings for group '$groupTargetLabel': $_"
                        $failureCount++
                    }
                }

                if ($ownerSettingsConfig) {
                    try {
                        $ownerPolicyConfig = if ($ownerSettingsConfig -is [hashtable]) { $ownerSettingsConfig } else { ConvertTo-Hashtable -InputObject $ownerSettingsConfig }
                        if (-not $ownerPolicyConfig.ContainsKey('PolicySource') -and -not $ownerPolicyConfig.ContainsKey('Settings') -and -not $ownerPolicyConfig.ContainsKey('Template')) {
                            $ownerPolicyConfig = @{ PolicySource = 'inline'; Settings = $ownerPolicyConfig }
                        }

                        $ownerSettings = Resolve-PIMTemplate -PolicyConfig $ownerPolicyConfig -Templates $templates
                        $preparedGroupWork.Add(@{ GroupName = $groupName; GroupId = $groupId; MemberType = 'owner'; Settings = $ownerSettings })
                    }
                    catch {
                        Write-Error "Failed to resolve owner settings for group '$groupTargetLabel': $_"
                        $failureCount++
                    }
                }

                continue
            }

            try {
                $settings = Resolve-PIMTemplate -PolicyConfig $groupPolicyConfig -Templates $templates
                $preparedGroupWork.Add(@{ GroupName = $groupName; GroupId = $groupId; MemberType = $memberType; Settings = $settings })
            }
            catch {
                Write-Error "Failed to resolve template for group '$groupTargetLabel': $_"
                $failureCount++
            }
        }
        #endregion

        $roleCount  = $preparedWork.Count
        $isWhatIf   = $WhatIfPreference -eq [System.Management.Automation.ActionPreference]::Continue
        $useParallel = $roleCount -gt 1 -and -not $isWhatIf

        Write-Host "`nProcessing $roleCount role(s)$(if ($useParallel) { ' in parallel' })..." -ForegroundColor Cyan

        #region Phase 2 — apply (parallel when >1 role and not -WhatIf)
        if ($useParallel) {
            $moduleBase  = (Get-Module PaC -ErrorAction SilentlyContinue)?.ModuleBase
            $accessToken = $script:PIMContext?.AccessToken

            if (-not $moduleBase) {
                Write-Warning "Cannot determine module base path — falling back to sequential processing."
                $useParallel = $false
            }
            else {
                $bag = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::new()

                $preparedWork | ForEach-Object -Parallel {
                    $modBase     = $using:moduleBase
                    $tok         = $using:accessToken
                    $resultBag   = $using:bag
                    $roleName    = $_.RoleName
                    $settings    = $_.Settings

                    Import-Module (Join-Path $modBase 'PaC.psd1') -Force -Verbose:$false 2>$null 3>$null 4>$null

                    # Restore Graph context in this runspace without triggering Connect-PIM output
                    $m = Get-Module PaC -ErrorAction SilentlyContinue
                    if ($m) {
                        & $m {
                            param($t)
                            $script:PIMContext = @{
                                TenantId    = $null
                                ClientId    = $null
                                AccessToken = $t
                                ExpiresAt   = $null
                                AuthMethod  = 'AccessToken'
                            }
                        } $tok
                    }

                    Write-Host "[$roleName] Starting..." -ForegroundColor Cyan
                    try {
                        Set-PIMRolePolicy -RoleName $roleName -Settings $settings
                        $resultBag.Add([PSCustomObject]@{ Name = $roleName; Success = $true })
                    }
                    catch {
                        Write-Error "[$roleName] $_"
                        $resultBag.Add([PSCustomObject]@{ Name = $roleName; Success = $false })
                    }
                } -ThrottleLimit 5

                $successCount += ($bag | Where-Object {  $_.Success } | Measure-Object).Count
                $failureCount += ($bag | Where-Object { -not $_.Success } | Measure-Object).Count
            }
        }

        if (-not $useParallel) {
            foreach ($work in $preparedWork) {
                $roleName = $work.RoleName
                $settings = $work.Settings

                Write-Host "`nRole '$roleName':" -ForegroundColor Cyan
                try {
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
        }
        #endregion

        #region Phase 3 — apply group policies (sequential)
        if ($preparedGroupWork.Count -gt 0) {
            Write-Host "`nProcessing $($preparedGroupWork.Count) group policy entr$(if ($preparedGroupWork.Count -eq 1) { 'y' } else { 'ies' })..." -ForegroundColor Cyan

            foreach ($work in $preparedGroupWork) {
                $groupName = $work.GroupName
                $groupId   = $work.GroupId
                $memberType = $work.MemberType
                $settings  = $work.Settings

                $targetLabel = if ($groupName) { "Group '$groupName'" } else { "Group '$groupId'" }
                Write-Host ("`n{0} ({1}):" -f $targetLabel, $memberType) -ForegroundColor Cyan

                try {
                    if ($PSCmdlet.ShouldProcess($targetLabel, 'Apply PIM group policy')) {
                        if ($groupId) {
                            Set-PIMGroupPolicy -GroupId $groupId -MemberType $memberType -Settings $settings
                        }
                        else {
                            Set-PIMGroupPolicy -GroupName $groupName -MemberType $memberType -Settings $settings
                        }
                        $successCount++
                    }
                }
                catch {
                    Write-Error ("Failed to process policy for {0}: {1}" -f $targetLabel, $_)
                    $failureCount++
                }
            }
        }
        #endregion

        #region Phase 4 — optional role-to-group assignments
        $groupAssignments = @()
        if ($config.RoleToGroupAssignments) {
            $groupAssignments += @($config.RoleToGroupAssignments)
        }
        if ($config.EntraRoles) {
            $entraRolesConfig = if ($config.EntraRoles -is [hashtable]) { $config.EntraRoles } else { ConvertTo-Hashtable -InputObject $config.EntraRoles }
            if ($entraRolesConfig['RoleToGroupAssignments']) {
                $groupAssignments += @($entraRolesConfig['RoleToGroupAssignments'])
            }
            if ($entraRolesConfig['GroupAssignments']) {
                $groupAssignments += @($entraRolesConfig['GroupAssignments'])
            }
        }

        if ($groupAssignments.Count -gt 0) {
            Write-Host "`nProcessing $($groupAssignments.Count) role-to-group assignment block(s)..." -ForegroundColor Cyan

            foreach ($rawAssignment in $groupAssignments) {
                $assignmentConfig = if ($rawAssignment -is [hashtable]) { $rawAssignment } else { ConvertTo-Hashtable -InputObject $rawAssignment }

                $groupName = $assignmentConfig['GroupName']
                $groupId   = $assignmentConfig['GroupId']

                if (-not $groupName -and -not $groupId) {
                    Write-Warning "Role-to-group assignment entry is missing 'GroupName' or 'GroupId'. Skipping."
                    $failureCount++
                    continue
                }

                $roleNames = @()
                $roleIds   = @()

                if ($assignmentConfig['RoleName']) {
                    $roleNames += @($assignmentConfig['RoleName'])
                }
                if ($assignmentConfig['RoleNames']) {
                    $roleNames += @($assignmentConfig['RoleNames'])
                }
                if ($assignmentConfig['RoleDefinitionId']) {
                    $roleIds += @($assignmentConfig['RoleDefinitionId'])
                }
                if ($assignmentConfig['RoleDefinitionIds']) {
                    $roleIds += @($assignmentConfig['RoleDefinitionIds'])
                }

                if ($roleNames.Count -eq 0 -and $roleIds.Count -eq 0) {
                    Write-Warning "Role-to-group assignment for group '$($groupName ?? $groupId)' is missing role references. Skipping."
                    $failureCount++
                    continue
                }

                try {
                    if ($PSCmdlet.ShouldProcess("Group '$($groupName ?? $groupId)'", 'Assign Entra roles to group')) {
                        if ($roleNames.Count -gt 0) {
                            if ($groupId) {
                                Set-PIMRoleGroupAssignment -GroupId $groupId -RoleName $roleNames
                            }
                            else {
                                Set-PIMRoleGroupAssignment -GroupName $groupName -RoleName $roleNames
                            }
                        }

                        if ($roleIds.Count -gt 0) {
                            if ($groupId) {
                                Set-PIMRoleGroupAssignment -GroupId $groupId -RoleDefinitionId $roleIds
                            }
                            else {
                                Set-PIMRoleGroupAssignment -GroupName $groupName -RoleDefinitionId $roleIds
                            }
                        }

                        $successCount++
                    }
                }
                catch {
                    Write-Error "Failed to process role-to-group assignment for group '$($groupName ?? $groupId)': $_"
                    $failureCount++
                }
            }
        }
        #endregion

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
