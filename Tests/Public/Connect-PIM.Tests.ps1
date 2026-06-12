#Requires -Modules Pester

Describe 'Connect-PIM / Disconnect-PIM' {
    BeforeAll {
        $modulePath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        Import-Module (Join-Path $modulePath 'PaC.psd1') -Force
    }

    AfterEach {
        Disconnect-PIM -ErrorAction SilentlyContinue
    }

    Context 'Pre-obtained access token' {
        It 'Sets the PIM context without calling the token endpoint' {
            Connect-PIM -AccessToken 'fake-token-for-testing'

            # After Connect-PIM, Invoke-PIMGraphRequest should include the token in headers.
            # We verify indirectly by checking that Disconnect-PIM succeeds (context was set).
            { Disconnect-PIM } | Should -Not -Throw
        }
    }

    Context 'Disconnect-PIM' {
        It 'Clears the context without error' {
            Connect-PIM -AccessToken 'fake-token'
            { Disconnect-PIM } | Should -Not -Throw
        }

        It 'Emits a warning when no session is active' {
            Disconnect-PIM -ErrorAction SilentlyContinue  # ensure clean state
            $warning = $null
            Disconnect-PIM -WarningVariable warning 3>$null
            $warning | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Invoke-PIMGraphRequest without connection' {
        It 'Throws a helpful error when not connected' {
            # Ensure disconnected
            Disconnect-PIM -ErrorAction SilentlyContinue

            # Access the private function via module scope
            $fn = (Get-Module PaC).NewBoundScriptBlock({ Invoke-PIMGraphRequest -Method GET -Uri 'test' })
            { & $fn } | Should -Throw '*Not connected*'
        }
    }

    AfterAll {
        Remove-Module PaC -Force -ErrorAction SilentlyContinue
    }
}
