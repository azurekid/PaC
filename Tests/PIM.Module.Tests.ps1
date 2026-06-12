#Requires -Modules Pester

Describe 'PaC Module' {
    BeforeAll {
        $modulePath = Split-Path -Parent $PSScriptRoot
        Import-Module (Join-Path $modulePath 'PaC.psd1') -Force
    }

    Context 'Module manifest' {
        BeforeAll {
            $manifestPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'PaC.psd1'
            $manifest     = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
        }

        It 'Has a valid manifest' {
            $manifest | Should -Not -BeNullOrEmpty
        }

        It 'Exports the expected public functions' {
            $expected = @(
                'Connect-PIM'
                'Disconnect-PIM'
                'Get-PIMRoleDefinition'
                'Get-PIMRolePolicy'
                'Set-PIMRolePolicy'
                'Invoke-PIMConfiguration'
            )
            foreach ($fn in $expected) {
                $manifest.ExportedFunctions.Keys | Should -Contain $fn
            }
        }

        It 'Does not export private functions' {
            $private = @(
                'Invoke-PIMGraphRequest'
                'Get-PIMRoleManagementPolicy'
                'Update-PIMPolicyRule'
                'Resolve-PIMTemplate'
                'ConvertTo-PIMPolicyRules'
            )
            foreach ($fn in $private) {
                $manifest.ExportedFunctions.Keys | Should -Not -Contain $fn
            }
        }

        It 'Requires PowerShell 7.0 or later' {
            $manifest.PowerShellVersion | Should -Be '7.0'
        }
    }

    AfterAll {
        Remove-Module PaC -Force -ErrorAction SilentlyContinue
    }
}
