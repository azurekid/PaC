function Resolve-PIMAccessToken {
    <#
    .SYNOPSIS
        Normalizes access token inputs into a plain JWT string.
    .DESCRIPTION
        Accepts common token input shapes used by PowerShell and Az modules,
        including plain strings, secure strings, and objects with token
        properties (Token/access_token/AccessToken).
    .PARAMETER InputObject
        The token source object.
    .OUTPUTS
        String.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$InputObject
    )

    if ($null -eq $InputObject) {
        throw 'Access token value is null.'
    }

    $token = $null

    if ($InputObject -is [System.Security.SecureString]) {
        $token = [System.Net.NetworkCredential]::new('', $InputObject).Password
    }
    elseif ($InputObject -is [string]) {
        $token = $InputObject
    }
    else {
        foreach ($prop in @('access_token', 'AccessToken', 'token', 'Token')) {
            if ($InputObject.PSObject.Properties.Match($prop).Count -gt 0) {
                $tokenValue = $InputObject.$prop
                if ($tokenValue -is [System.Security.SecureString]) {
                    $token = [System.Net.NetworkCredential]::new('', $tokenValue).Password
                }
                else {
                    $token = [string]$tokenValue
                }
                break
            }
        }

        if (-not $token) {
            $token = [string]$InputObject
        }
    }

    $token = [string]$token
    $token = $token.Trim()
    $token = [System.Text.RegularExpressions.Regex]::Replace($token, '^Bearer\s+', '', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $token = ($token -replace '\s', '')

    if ([string]::IsNullOrWhiteSpace($token)) {
        throw 'Access token is empty after normalization.'
    }

    $dotCount = ([regex]::Matches($token, '\.')).Count
    if ($dotCount -ne 2 -and $dotCount -ne 4) {
        throw "Access token is not in JWT compact format (expected 2 or 4 dots, got $dotCount)."
    }

    return $token
}