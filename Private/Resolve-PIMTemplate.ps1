function Resolve-PIMTemplate {
    <#
    .SYNOPSIS
        Resolves and merges a policy template with optional per-role overrides.
    .DESCRIPTION
        Internal helper. Returns a merged settings hashtable by starting with the
        named template and then applying any property-level overrides on top.
        If PolicySource is 'inline', overrides are applied directly to an empty base.
    .PARAMETER PolicyConfig
        A hashtable representing one entry from EntraRoles.Policies.
    .PARAMETER Templates
        A hashtable of all available policy templates keyed by template name.
    .OUTPUTS
        Hashtable — the merged settings ready to be converted to Graph API rules.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory)]
        [hashtable]$PolicyConfig,

        [Parameter()]
        [hashtable]$Templates = @{}
    )

    $policySource = $PolicyConfig['PolicySource'] ?? 'inline'

    switch ($policySource.ToLower()) {
        'template' {
            $templateName = $PolicyConfig['Template']
            if (-not $templateName) {
                throw "PolicySource is 'template' but no 'Template' name was specified for role '$($PolicyConfig['RoleName'])'."
            }
            if (-not $Templates.ContainsKey($templateName)) {
                throw "Template '$templateName' was not found. Available templates: $($Templates.Keys -join ', ')."
            }

            # Deep-copy the template to avoid mutating the original
            $merged = @{}
            foreach ($key in $Templates[$templateName].Keys) {
                $value = $Templates[$templateName][$key]
                if ($value -is [hashtable]) {
                    $nested = @{}
                    foreach ($nk in $value.Keys) { $nested[$nk] = $value[$nk] }
                    $merged[$key] = $nested
                }
                else {
                    $merged[$key] = $value
                }
            }

            # Apply per-role overrides (if any) on top of the template
            $overrides = $PolicyConfig['Override']
            if ($overrides) {
                $overrideTable = if ($overrides -is [hashtable]) { $overrides } else { ConvertTo-Hashtable $overrides }
                foreach ($key in $overrideTable.Keys) {
                    $value = $overrideTable[$key]
                    if ($value -is [hashtable] -and $merged.ContainsKey($key) -and $merged[$key] -is [hashtable]) {
                        foreach ($nk in $value.Keys) { $merged[$key][$nk] = $value[$nk] }
                    }
                    else {
                        $merged[$key] = $value
                    }
                }
            }

            return $merged
        }
        'inline' {
            $settings = $PolicyConfig['Settings']
            if (-not $settings) {
                throw "PolicySource is 'inline' but no 'Settings' block was provided for role '$($PolicyConfig['RoleName'])'."
            }
            if ($settings -is [hashtable]) { return $settings }
            return ConvertTo-Hashtable -InputObject $settings
        }
        default {
            throw "Unknown PolicySource '$policySource'. Valid values are 'template' and 'inline'."
        }
    }
}

function ConvertTo-Hashtable {
    <#
    .SYNOPSIS
        Recursively converts a PSCustomObject to a hashtable.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory)]
        $InputObject
    )

    if ($InputObject -is [hashtable]) { return $InputObject }

    $result = @{}
    foreach ($property in $InputObject.PSObject.Properties) {
        $value = $property.Value
        if ($value -is [PSCustomObject]) {
            $result[$property.Name] = ConvertTo-Hashtable -InputObject $value
        }
        elseif ($value -is [System.Collections.IList] -and $value -isnot [string]) {
            $result[$property.Name] = @($value | ForEach-Object {
                if ($_ -is [PSCustomObject]) { ConvertTo-Hashtable -InputObject $_ } else { $_ }
            })
        }
        else {
            $result[$property.Name] = $value
        }
    }
    return $result
}
