function Invoke-PIMGraphRequest {
    <#
    .SYNOPSIS
        Sends an authenticated request to the Microsoft Graph API.
    .DESCRIPTION
        Internal helper that wraps Invoke-RestMethod with the current PIM context
        (access token) and handles paging via @odata.nextLink automatically.
    .PARAMETER Method
        HTTP method (GET, POST, PATCH, DELETE).
    .PARAMETER Uri
        Graph API URI (relative path or full URL).
    .PARAMETER Body
        Request body (hashtable or PSObject) serialised to JSON automatically.
    .PARAMETER ExpandNextLink
        When specified, follows @odata.nextLink to retrieve all pages.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter()]
        [object]$Body,

        [Parameter()]
        [switch]$ExpandNextLink
    )

    if (-not $script:PIMContext) {
        throw 'Not connected to Microsoft Graph. Run Connect-PIM first.'
    }

    $baseUri = 'https://graph.microsoft.com/v1.0'
    if ($Uri -notmatch '^https?://') {
        $Uri = "$baseUri/$($Uri.TrimStart('/'))"
    }

    $headers = @{
        Authorization  = "Bearer $($script:PIMContext.AccessToken)"
        'Content-Type' = 'application/json'
        'Accept'       = 'application/json'
    }

    $params = @{
        Method  = $Method
        Uri     = $Uri
        Headers = $headers
    }

    if ($Body) {
        $params['Body'] = ($Body | ConvertTo-Json -Depth 20 -Compress)
    }

    try {
        $response = Invoke-RestMethod @params -ErrorAction Stop

        if ($ExpandNextLink) {
            $allValues = [System.Collections.Generic.List[PSCustomObject]]::new()
            if ($response.value) {
                $allValues.AddRange([PSCustomObject[]]$response.value)
            }
            $nextLink = $response.'@odata.nextLink'
            while ($nextLink) {
                $params['Uri'] = $nextLink
                $params.Remove('Body') | Out-Null
                $page      = Invoke-RestMethod @params -ErrorAction Stop
                if ($page.value) {
                    $allValues.AddRange([PSCustomObject[]]$page.value)
                }
                $nextLink  = $page.'@odata.nextLink'
            }
            return $allValues
        }

        return $response
    }
    catch [System.Net.Http.HttpRequestException] {
        Write-Error "Graph API request failed ($Method $Uri): $_"
        throw
    }
    catch {
        $errorMessage = $_
        if ($_.Exception.Response) {
            try {
                $reader  = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                $details = $reader.ReadToEnd() | ConvertFrom-Json -ErrorAction SilentlyContinue
                $errorMessage = $details.error.message ?? $_
            }
            catch { }
        }
        Write-Error "Graph API request failed ($Method $Uri): $errorMessage"
        throw
    }
}
