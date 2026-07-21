function Set-PIMGroupPolicy {
    <#
    .SYNOPSIS
        Applies PIM for Groups policy settings to one or more groups.
    .DESCRIPTION
        Converts the provided settings hashtable into Graph policy rules and patches
        changed rules on the role management policy assigned to each group.

        Supported settings keys match ConvertTo-PIMPolicyRules.
        
        You can specify policy settings either directly via -Settings, or via a named
        template (-Template) with optional per-group overrides (-Override).
    .PARAMETER GroupName
        One or more Microsoft Entra group display names.
    .PARAMETER GroupId
        One or more Microsoft Entra group object IDs.
    .PARAMETER Settings
        Hashtable of policy settings to apply. Use with the 'Inline' parameter set.
    .PARAMETER Template
        Name of a predefined policy template. Use with the 'Template' parameter set.
    .PARAMETER Override
        Hashtable of policy settings to override the template values.
    .PARAMETER Templates
        Hashtable of available templates. When omitted, templates are loaded
        from TemplateDirectory or common default template folders.
    .PARAMETER TemplateDirectory
        Optional path to a directory containing JSON or YAML templates.
        When omitted, the cmdlet tries common defaults such as ./Templates
        and ./Examples/Templates.
    .PARAMETER MemberType
        Group assignment type to target: member, owner, or both.
    .PARAMETER PassThru
        Returns simplified group policy after update.
    #>
    [CmdletBinding(DefaultParameterSetName = 'ByNameInline', SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, ParameterSetName = 'ByNameInline', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Parameter(Mandatory, ParameterSetName = 'ByNameTemplate', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$GroupName,

        [Parameter(Mandatory, ParameterSetName = 'ByIdInline')]
        [Parameter(Mandatory, ParameterSetName = 'ByIdTemplate')]
        [string[]]$GroupId,

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

        [Parameter(ParameterSetName = 'ByNameTemplate')]
        [Parameter(ParameterSetName = 'ByIdTemplate')]
        [string]$TemplateDirectory,

        [Parameter()]
        [ValidateSet('member', 'owner', 'both')]
        [string]$MemberType = 'member',

        [Parameter()]
        [switch]$PassThru
    )

    process {
        # Resolve template if specified
        if ($PSCmdlet.ParameterSetName -like '*Template*') {
            if ($Templates.Count -eq 0) {
                $candidateDirectories = [System.Collections.Generic.List[string]]::new()

                if ($TemplateDirectory) {
                    $candidateDirectories.Add($TemplateDirectory)
                }
                else {
                    $candidateDirectories.Add((Join-Path (Get-Location).Path 'Templates'))

                    $moduleRoot = Split-Path -Parent $PSScriptRoot
                    $candidateDirectories.Add((Join-Path $moduleRoot 'Templates'))
                }

                foreach ($dir in ($candidateDirectories | Where-Object { $_ } | Select-Object -Unique)) {
                    if (-not (Test-Path -Path $dir -PathType Container)) {
                        continue
                    }

                    $templateFiles = Get-ChildItem -Path $dir -File | Where-Object { $_.Extension -in @('.json', '.yml', '.yaml') }

                    foreach ($file in $templateFiles) {
                        try {
                            $templateContent = if (Get-Command -Name Import-PIMConfigFile -ErrorAction SilentlyContinue) {
                                Import-PIMConfigFile -Path $file.FullName
                            }
                            elseif ($file.Extension -eq '.json') {
                                Get-Content -Path $file.FullName -Raw | ConvertFrom-Json -Depth 100
                            }
                            else {
                                throw "YAML template parsing requires Invoke-PIMConfiguration helpers."
                            }

                            $Templates[$file.BaseName] = if ($templateContent -is [hashtable]) {
                                $templateContent
                            }
                            else {
                                ConvertTo-Hashtable -InputObject $templateContent
                            }
                        }
                        catch {
                            Write-Verbose "Skipping template file '$($file.FullName)': $_"
                        }
                    }
                }
            }

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

            # Apply per-group overrides (if any) on top of the template
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

        $groupTargets = [System.Collections.Generic.List[hashtable]]::new()

        if ($PSCmdlet.ParameterSetName -like 'ByName*') {
            foreach ($name in $GroupName) {
                $escapedName = $name.Replace("'", "''")
                $groupFilter = "displayName eq '$escapedName'"
                $uri = "groups?`$filter=$([uri]::EscapeDataString($groupFilter))&`$select=id,displayName"
                $groupMatch = Invoke-PIMGraphRequest -Method GET -Uri $uri -ExpandNextLink

                if (-not $groupMatch -or $groupMatch.Count -eq 0) {
                    Write-Warning "Group '$name' was not found. Skipping."
                    continue
                }

                $exact = @($groupMatch | Where-Object { $_.displayName -eq $name } | Select-Object -First 1)
                if (-not $exact) {
                    $exact = @($groupMatch | Select-Object -First 1)
                }

                $groupTargets.Add(@{ Id = $exact[0].id; Name = $exact[0].displayName })
            }
        }
        else {
            foreach ($id in $GroupId) {
                try {
                    $group = Invoke-PIMGraphRequest -Method GET -Uri "groups/$id?`$select=id,displayName"
                    $groupTargets.Add(@{ Id = $group.id; Name = $group.displayName })
                }
                catch {
                    Write-Warning "Group ID '$id' was not found. Skipping."
                }
            }
        }

        $rules = ConvertTo-PIMPolicyRules -Settings $Settings
        if ($rules.Count -eq 0) {
            Write-Warning 'No policy rules were generated from the provided settings. Nothing to apply.'
            return
        }

        $memberTypesToProcess = if ($MemberType -eq 'both') { @('member', 'owner') } else { @($MemberType) }

        foreach ($group in $groupTargets) {
            foreach ($resolvedMemberType in $memberTypesToProcess) {
                if (-not $PSCmdlet.ShouldProcess("Group '$($group.Name)' ($resolvedMemberType)", 'Apply PIM group policy settings')) {
                    continue
                }

                try {
                    $policy = Get-PIMGroupManagementPolicy -GroupId $group.Id -MemberType $resolvedMemberType

                    $currentIndex = @{}
                    foreach ($r in $policy.rules) {
                        $currentIndex[$r.id] = $r
                    }

                    $changedCount = 0
                    $skippedCount = 0
                    $unsupportedCount = 0
                    $total = $rules.Count
                    $i = 0

                    foreach ($rule in $rules) {
                        $i++
                        $ruleId = $rule['id']
                        $currentRule = $currentIndex[$ruleId]

                        Write-Progress -Id 2 `
                            -Activity "Applying group policy: $($group.Name) ($resolvedMemberType)" `
                            -Status "[$i/$total] $ruleId" `
                            -PercentComplete ([Math]::Floor(($i / $total) * 100))

                        if (-not (Test-PIMRuleChanged -Desired $rule -Current $currentRule)) {
                            Write-Host "  [=] $ruleId" -ForegroundColor DarkGray
                            $skippedCount++
                            continue
                        }

                        Write-Host "  [~] $ruleId" -ForegroundColor Cyan
                        try {
                            Update-PIMPolicyRule -PolicyId $policy.id -Rule $rule
                            $changedCount++
                        }
                        catch {
                            $err = $_ | Out-String
                            $isUnsupportedRule = $err -match 'InvalidPolicyRuleId|InvalidPolicyRuleProperty|policy rule id .* is invalid|property value of .* of rule id .* is invalid'

                            if ($isUnsupportedRule) {
                                Write-Warning "Rule '$ruleId' is not available on this group policy and was skipped."
                                $unsupportedCount++
                                continue
                            }

                            throw
                        }
                    }

                    Write-Progress -Id 2 -Activity "Applying group policy: $($group.Name) ($resolvedMemberType)" -Completed

                    if ($changedCount -gt 0 -or $unsupportedCount -gt 0) {
                        Write-Host "  Group '$($group.Name)' ($resolvedMemberType): $changedCount rule(s) updated, $skippedCount unchanged, $unsupportedCount unsupported." -ForegroundColor Green
                    }
                    else {
                        Write-Host "  Group '$($group.Name)' ($resolvedMemberType): already up-to-date (0 changes)." -ForegroundColor DarkGreen
                    }

                    if ($PassThru) {
                        Get-PIMGroupPolicy -GroupId $group.Id
                    }
                }
                catch {
                    Write-Error "Failed to apply policy to group '$($group.Name)' ($resolvedMemberType): $_"
                    throw
                }
            }
        }
    }
}
