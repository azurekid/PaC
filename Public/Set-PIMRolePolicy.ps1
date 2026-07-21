function Set-PIMRolePolicy {
    <#
    .SYNOPSIS
        Applies PIM policy settings to one or more Entra ID roles.
    .DESCRIPTION
        Converts the provided settings hashtable into Microsoft Graph API rule
        objects and patches each changed rule on the role's management policy.
        Rules that already match the current policy are skipped automatically.

        Supported settings keys: see ConvertTo-PIMPolicyRules for the full list.
        
        You can specify policy settings either directly via -Settings, or via a named
        template (-Template) with optional per-role overrides (-Override).
    .PARAMETER RoleName
        One or more Entra ID role display names.
    .PARAMETER RoleDefinitionId
        One or more Entra ID role definition GUIDs.
    .PARAMETER Settings
        A hashtable of policy settings to apply. Use with the 'Inline' parameter set.
    .PARAMETER Template
        Name of a predefined policy template. Use with the 'Template' parameter set.
    .PARAMETER Override
        Hashtable of policy settings to override the template values.
    .PARAMETER Templates
        Hashtable of available templates. Required when using -Template.
    .PARAMETER PassThru
        When specified, returns the updated simplified policy object for each role.
    .EXAMPLE
        Set-PIMRolePolicy -RoleName 'Security Administrator' -Settings @{
            ActivationDuration         = 'PT4H'
            ActivationRequirement      = 'MultiFactorAuthentication,Justification'
            ApprovalRequired           = $false
            AllowPermanentEligibility  = $false
            MaximumEligibilityDuration = 'P180D'
        }
    .EXAMPLE
        # Preview changes without applying them
        Set-PIMRolePolicy -RoleName 'Global Administrator' -Settings @{ApprovalRequired = $true} -WhatIf
    .EXAMPLE
        # Apply settings from a template
        $templates = @{
            HighSecurity = @{
                ActivationDuration         = 'PT4H'
                ApprovalRequired           = $true
                AllowPermanentEligibility  = $false
            }
        }
        Set-PIMRolePolicy -RoleName 'Security Administrator' -Template 'HighSecurity' -Templates $templates
    #>
    [CmdletBinding(DefaultParameterSetName = 'ByNameInline', SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, ParameterSetName = 'ByNameInline', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Parameter(Mandatory, ParameterSetName = 'ByNameTemplate', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$RoleName,

        [Parameter(Mandatory, ParameterSetName = 'ByIdInline')]
        [Parameter(Mandatory, ParameterSetName = 'ByIdTemplate')]
        [string[]]$RoleDefinitionId,

        [Parameter(Mandatory, ParameterSetName = 'ByNameInline')]
        [Parameter(Mandatory, ParameterSetName = 'ByIdInline')]
        [hashtable]$Settings,

        [Parameter(Mandatory, ParameterSetName = 'ByNameTemplate')]
        [Parameter(Mandatory, ParameterSetName = 'ByIdTemplate')]
        [string]$Template,

        [Parameter(ParameterSetName = 'ByNameTemplate')]
        [Parameter(ParameterSetName = 'ByIdTemplate')]
        [hashtable]$Override,

        [Parameter(ParameterSetName = 'ByNameTemplate')]
        [Parameter(ParameterSetName = 'ByIdTemplate')]
        [hashtable]$Templates = @{},

        [Parameter()]
        [switch]$PassThru
    )

    process {
        # Resolve template if specified
        if ($PSCmdlet.ParameterSetName -like '*Template*') {
            if (-not $Templates.ContainsKey($Template)) {
                throw "Template '$Template' was not found. Available templates: $($Templates.Keys -join ', ')."
            }

            # Deep-copy the template to avoid mutating the original
            $resolvedSettings = @{}
            foreach ($key in $Templates[$Template].Keys) {
                $value = $Templates[$Template][$key]
                if ($value -is [hashtable]) {
                    $nested = @{}
                    foreach ($nk in $value.Keys) { $nested[$nk] = $value[$nk] }
                    $resolvedSettings[$key] = $nested
                }
                else {
                    $resolvedSettings[$key] = $value
                }
            }

            # Apply per-role overrides (if any) on top of the template
            if ($Override) {
                foreach ($key in $Override.Keys) {
                    $value = $Override[$key]
                    if ($value -is [hashtable] -and $resolvedSettings.ContainsKey($key) -and $resolvedSettings[$key] -is [hashtable]) {
                        foreach ($nk in $value.Keys) { $resolvedSettings[$key][$nk] = $value[$nk] }
                    }
                    else {
                        $resolvedSettings[$key] = $value
                    }
                }
            }
            $Settings = $resolvedSettings
        }

        $roleTargets = [System.Collections.Generic.List[hashtable]]::new()

        if ($PSCmdlet.ParameterSetName -like 'ByName*') {
            foreach ($name in $RoleName) {
                $roleDef = Get-PIMRoleDefinition -DisplayName $name | Where-Object { $_.displayName -ieq $name }
                if (-not $roleDef) {
                    Write-Warning "Role '$name' was not found. Skipping."
                    continue
                }
                $roleTargets.Add(@{ Id = $roleDef.id; Name = $roleDef.displayName })
            }
        }
        else {
            foreach ($id in $RoleDefinitionId) {
                try {
                    $roleDef = Get-PIMRoleDefinition -RoleDefinitionId $id
                    $roleTargets.Add(@{ Id = $roleDef.id; Name = $roleDef.displayName })
                }
                catch {
                    Write-Warning "Role definition ID '$id' was not found. Skipping."
                }
            }
        }

        $rules = ConvertTo-PIMPolicyRules -Settings $Settings

        if ($rules.Count -eq 0) {
            Write-Warning "No policy rules were generated from the provided settings. Nothing to apply."
            return
        }

        foreach ($role in $roleTargets) {
            if (-not $PSCmdlet.ShouldProcess("Role '$($role.Name)'", 'Apply PIM policy settings')) {
                continue
            }

            try {
                Write-Verbose "Retrieving policy for role '$($role.Name)'..."
                $policy = Get-PIMRoleManagementPolicy -RoleDefinitionId $role.Id

                # Index current rules by id for fast lookup
                $currentIndex = @{}
                foreach ($r in $policy.rules) {
                    $currentIndex[$r.id] = $r
                }

                $changedCount = 0
                $skippedCount = 0
                $unsupportedCount = 0
                $total        = $rules.Count
                $i            = 0

                foreach ($rule in $rules) {
                    $i++
                    $ruleId      = $rule['id']
                    $currentRule = $currentIndex[$ruleId]

                    Write-Progress -Id 1 `
                        -Activity "Applying policy: $($role.Name)" `
                        -Status   "[$i/$total] $ruleId" `
                        -PercentComplete ([Math]::Floor(($i / $total) * 100))

                    if (-not (Test-PIMRuleChanged -Desired $rule -Current $currentRule)) {
                        Write-Host "  [=] $ruleId" -ForegroundColor DarkGray
                        $skippedCount++
                        continue
                    }

                    Write-Verbose "Patching rule '$ruleId' on policy '$($policy.id)'..."
                    Write-Host "  [~] $ruleId" -ForegroundColor Cyan
                    try {
                        Update-PIMPolicyRule -PolicyId $policy.id -Rule $rule
                        $changedCount++
                    }
                    catch {
                        $err = $_ | Out-String
                        $isUnsupportedRule = $err -match 'InvalidPolicyRuleId|InvalidPolicyRuleProperty|policy rule id .* is invalid|property value of .* of rule id .* is invalid'

                        if ($isUnsupportedRule) {
                            Write-Warning "Rule '$ruleId' is not available on this policy and was skipped."
                            $unsupportedCount++
                            continue
                        }

                        throw
                    }
                }

                Write-Progress -Id 1 -Activity "Applying policy: $($role.Name)" -Completed

                if ($changedCount -gt 0 -or $unsupportedCount -gt 0) {
                    Write-Host "  Role '$($role.Name)': $changedCount rule(s) updated, $skippedCount unchanged, $unsupportedCount unsupported." -ForegroundColor Green
                }
                else {
                    Write-Host "  Role '$($role.Name)': already up-to-date (0 changes)." -ForegroundColor DarkGreen
                }

                if ($PassThru) {
                    Get-PIMRolePolicy -RoleDefinitionId $role.Id
                }
            }
            catch {
                Write-Error "Failed to apply policy to role '$($role.Name)': $_"
                throw
            }
        }
    }
}
