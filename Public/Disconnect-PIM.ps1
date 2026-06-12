function Disconnect-PIM {
    <#
    .SYNOPSIS
        Disconnects from the Microsoft Graph API and clears the PIM session context.
    .DESCRIPTION
        Clears the stored access token and connection metadata, ending the current
        PIM session. Run this when you have finished making PIM changes to avoid
        leaving credentials in memory.
    .EXAMPLE
        Disconnect-PIM
    #>
    [CmdletBinding()]
    param ()

    if ($null -eq $script:PIMContext) {
        Write-Warning "No active PIM session found. Nothing to disconnect."
        return
    }

    $script:PIMContext = $null
    Write-Host "Disconnected from Microsoft Graph." -ForegroundColor Yellow
}
