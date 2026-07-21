function Connect-PIM {
    <#
    .SYNOPSIS
        Connects to the Microsoft Graph API for PIM operations.
    .DESCRIPTION
        Establishes an authenticated session with Microsoft Graph.
        Supports three authentication methods:

          1. Service principal (client credentials) — for automation pipelines.
          2. Device code flow — for interactive use when no browser is available.
          3. Pre-obtained access token — when authentication is handled externally.
    .PARAMETER TenantId
        The Azure AD / Entra ID tenant ID (GUID or domain name).
    .PARAMETER ClientId
        The application (client) ID of the service principal.
    .PARAMETER ClientSecret
        The client secret for service-principal authentication.
    .PARAMETER AccessToken
        A pre-obtained access token. Use this parameter to integrate with
        an existing authentication mechanism (e.g. managed identity, MSAL.PS).
    .PARAMETER DeviceCode
        When specified, initiates the OAuth 2.0 device-code flow for interactive
        sign-in without a browser.
    .EXAMPLE
        # Service principal
        Connect-PIM -TenantId 'contoso.onmicrosoft.com' `
                    -ClientId  '00000000-0000-0000-0000-000000000000' `
                    -ClientSecret (ConvertTo-SecureString 'secret' -AsPlainText -Force)
    .EXAMPLE
        # Device code flow
        Connect-PIM -TenantId 'contoso.onmicrosoft.com' `
                    -ClientId  '00000000-0000-0000-0000-000000000000' `
                    -DeviceCode
    .EXAMPLE
        # Pre-obtained token
        $token = (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com').Token
        Connect-PIM -AccessToken $token
    #>
    [CmdletBinding(DefaultParameterSetName = 'ClientSecret')]
    param (
        [Parameter(Mandatory, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory, ParameterSetName = 'DeviceCode')]
        [string]$TenantId,

        [Parameter(Mandatory, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory, ParameterSetName = 'DeviceCode')]
        [string]$ClientId,

        [Parameter(Mandatory, ParameterSetName = 'ClientSecret')]
        [System.Security.SecureString]$ClientSecret,

        [Parameter(Mandatory, ParameterSetName = 'AccessToken')]
        [object]$AccessToken,

        [Parameter(Mandatory, ParameterSetName = 'DeviceCode')]
        [switch]$DeviceCode
    )

    switch ($PSCmdlet.ParameterSetName) {

        'ClientSecret' {
            $plainSecret = [System.Net.NetworkCredential]::new('', $ClientSecret).Password
            $body = @{
                grant_type    = 'client_credentials'
                client_id     = $ClientId
                client_secret = $plainSecret
                scope         = 'https://graph.microsoft.com/.default'
            }

            try {
                $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
                $response = Invoke-RestMethod -Method POST -Uri $tokenUri -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
                $script:PIMContext = @{
                    TenantId    = $TenantId
                    ClientId    = $ClientId
                    AccessToken = $response.access_token
                    ExpiresAt   = (Get-Date).AddSeconds($response.expires_in)
                    AuthMethod  = 'ClientSecret'
                }
                Write-Verbose "Connected to Microsoft Graph (tenant: $TenantId) using client credentials."
            }
            catch {
                throw "Failed to obtain access token: $_"
            }
        }

        'DeviceCode' {
            $dcBody = @{
                client_id = $ClientId
                scope     = 'https://graph.microsoft.com/RoleManagement.Read.Directory https://graph.microsoft.com/RoleManagement.ReadWrite.Directory https://graph.microsoft.com/RoleManagementPolicy.Read.Directory https://graph.microsoft.com/RoleManagementPolicy.ReadWrite.Directory offline_access'
            }

            try {
                $dcUri      = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"
                $dcResponse = Invoke-RestMethod -Method POST -Uri $dcUri -Body $dcBody -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop

                Write-Host $dcResponse.message

                $tokenUri  = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
                $pollBody  = @{
                    grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                    client_id   = $ClientId
                    device_code = $dcResponse.device_code
                }

                $interval   = $dcResponse.interval ?? 5
                $expiration = (Get-Date).AddSeconds($dcResponse.expires_in)

                while ((Get-Date) -lt $expiration) {
                    Start-Sleep -Seconds $interval
                    try {
                        $tokenResponse = Invoke-RestMethod -Method POST -Uri $tokenUri -Body $pollBody -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
                        $script:PIMContext = @{
                            TenantId    = $TenantId
                            ClientId    = $ClientId
                            AccessToken = $tokenResponse.access_token
                            ExpiresAt   = (Get-Date).AddSeconds($tokenResponse.expires_in)
                            AuthMethod  = 'DeviceCode'
                        }
                        Write-Verbose "Connected to Microsoft Graph (tenant: $TenantId) via device code flow."
                        Write-verbose "token: $($tokenResponse.access_token)"
                        return
                    }
                    catch {
                        $errorContent = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                        if ($errorContent.error -eq 'authorization_pending') { continue }
                        if ($errorContent.error -eq 'slow_down') { $interval += 5; continue }
                        throw "Device code token poll failed: $_"
                    }
                }
                throw 'Device code authentication timed out. Please try again.'
            }
            catch {
                throw "Device code flow failed: $_"
            }
        }

        'AccessToken' {
            $normalizedToken = Resolve-PIMAccessToken -InputObject $AccessToken
            $script:PIMContext = @{
                TenantId    = $null
                ClientId    = $null
                AccessToken = $normalizedToken
                ExpiresAt   = $null
                AuthMethod  = 'AccessToken'
            }
            Write-Verbose "Connected to Microsoft Graph using a pre-obtained access token."
            Write-Verbose "token: $normalizedToken"
        }
    }

    Write-Host "Successfully connected to Microsoft Graph." -ForegroundColor Green
}
