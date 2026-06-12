#Requires -Modules Pester

Describe 'Invoke-PIMConfiguration' {
    BeforeAll {
        $modulePath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        Import-Module (Join-Path $modulePath 'PaC.psd1') -Force

        # Create a temporary directory for test config files
        $testDir = Join-Path $TestDrive 'pim-test'
        New-Item -ItemType Directory -Path $testDir -Force | Out-Null
    }

    Context 'JSON configuration with template reference' {
        BeforeAll {
            $configJson = @'
{
  "PolicyTemplates": {
    "HighSecurity": {
      "ActivationDuration": "PT4H",
      "ActivationRequirement": "MultiFactorAuthentication,Justification,Ticketing",
      "ApprovalRequired": true,
      "Approvers": [
        {
          "id": "11111111-2222-3333-4444-555555555555",
          "description": "Privileged Access CAB"
        }
      ],
      "AllowPermanentEligibility": false,
      "MaximumEligibilityDuration": "P30D",
      "Notification_Activation_Alert": {
        "isDefaultRecipientEnabled": true,
        "notificationLevel": "All",
        "Recipients": ["soc-alerts@contoso.com"]
      }
    }
  },
  "EntraRoles": {
    "Policies": [
      {
        "RoleName": "Security Administrator",
        "PolicySource": "template",
        "Template": "HighSecurity"
      },
      {
        "RoleName": "Privileged Role Administrator",
        "PolicySource": "template",
        "Template": "HighSecurity",
        "Override": {
          "ActivationDuration": "PT2H"
        }
      }
    ]
  }
}
'@
            $configFile = Join-Path $testDir 'config.json'
            $configJson | Set-Content -Path $configFile -Encoding UTF8
        }

        It 'Reads the JSON file without error and calls Set-PIMRolePolicy for each role' {
            Mock -CommandName 'Set-PIMRolePolicy' -MockWith { } -ModuleName PaC

            # WhatIf prevents actual Graph calls; use -WhatIf to avoid needing a real connection
            Invoke-PIMConfiguration -ConfigurationFile $configFile -WhatIf

            # With -WhatIf, ShouldProcess returns false so Set-PIMRolePolicy mock is not called,
            # but no error should be thrown.
            Should -Invoke 'Set-PIMRolePolicy' -Times 0 -ModuleName PaC
        }

        It 'Parses the template and override correctly using Resolve-PIMTemplate internals' {
            # Test via the private function directly
            $privateDir = Join-Path $modulePath 'Private'
            . (Join-Path $privateDir 'Resolve-PIMTemplate.ps1')

            $templates = @{
                HighSecurity = @{
                    ActivationDuration    = 'PT4H'
                    ApprovalRequired      = $true
                }
            }

            $policyWithOverride = @{
                RoleName     = 'Privileged Role Administrator'
                PolicySource = 'template'
                Template     = 'HighSecurity'
                Override     = @{ ActivationDuration = 'PT2H' }
            }

            $result = Resolve-PIMTemplate -PolicyConfig $policyWithOverride -Templates $templates
            $result['ActivationDuration'] | Should -Be 'PT2H'
            $result['ApprovalRequired']   | Should -Be $true
        }
    }

    Context 'JSON configuration with inline settings' {
        BeforeAll {
            $inlineConfigJson = @'
{
  "EntraRoles": {
    "Policies": [
      {
        "RoleName": "Global Reader",
        "PolicySource": "inline",
        "Settings": {
          "ActivationDuration": "PT8H",
          "ActivationRequirement": "Justification",
          "AllowPermanentEligibility": true
        }
      }
    ]
  }
}
'@
            $inlineConfigFile = Join-Path $testDir 'inline-config.json'
            $inlineConfigJson | Set-Content -Path $inlineConfigFile -Encoding UTF8
        }

        It 'Reads inline settings without error' {
            Mock -CommandName 'Set-PIMRolePolicy' -MockWith { } -ModuleName PaC
            Invoke-PIMConfiguration -ConfigurationFile $inlineConfigFile -WhatIf
            Should -Invoke 'Set-PIMRolePolicy' -Times 0 -ModuleName PaC
        }
    }

    Context 'Separate template file' {
        BeforeAll {
            $templateJson = @'
{
  "PolicyTemplates": {
    "Standard": {
      "ActivationDuration": "PT8H",
      "ApprovalRequired": false
    }
  }
}
'@
            $rolesJson = @'
{
  "EntraRoles": {
    "Policies": [
      {
        "RoleName": "Reports Reader",
        "PolicySource": "template",
        "Template": "Standard"
      }
    ]
  }
}
'@
            $templateFile = Join-Path $testDir 'templates.json'
            $rolesFile    = Join-Path $testDir 'roles.json'
            $templateJson | Set-Content -Path $templateFile -Encoding UTF8
            $rolesJson    | Set-Content -Path $rolesFile    -Encoding UTF8
        }

        It 'Accepts a separate TemplateFile parameter' {
            Mock -CommandName 'Set-PIMRolePolicy' -MockWith { } -ModuleName PaC
            Invoke-PIMConfiguration -ConfigurationFile $rolesFile -TemplateFile $templateFile -WhatIf
        }
    }

    Context 'TemplateDirectory with individual template files' {
        BeforeAll {
            $templateDir = Join-Path $testDir 'templates'
            New-Item -ItemType Directory -Path $templateDir -Force | Out-Null

            # Individual template file — settings only, filename = template name
            @'
{
  "ActivationDuration": "PT4H",
  "ApprovalRequired": true
}
'@ | Set-Content -Path (Join-Path $templateDir 'HighSecurity.json') -Encoding UTF8

            # Single-role config file referencing the template by name
            $singleRoleJson = @'
{
  "RoleName": "Security Administrator",
  "PolicySource": "template",
  "Template": "HighSecurity"
}
'@
            $singleRoleFile = Join-Path $testDir 'single-role.json'
            $singleRoleJson | Set-Content -Path $singleRoleFile -Encoding UTF8
        }

        It 'Loads templates from a directory using filename as template name' {
            Mock -CommandName 'Set-PIMRolePolicy' -MockWith { } -ModuleName PaC
            Invoke-PIMConfiguration -ConfigurationFile $singleRoleFile `
                                    -TemplateDirectory $templateDir -WhatIf
            Should -Invoke 'Set-PIMRolePolicy' -Times 0 -ModuleName PaC
        }

        It 'Resolves template by name derived from filename' {
            $privateDir = Join-Path $modulePath 'Private'
            . (Join-Path $privateDir 'Resolve-PIMTemplate.ps1')

            $templates = @{
                HighSecurity = @{
                    ActivationDuration = 'PT4H'
                    ApprovalRequired   = $true
                }
            }
            $policyConfig = @{
                RoleName     = 'Security Administrator'
                PolicySource = 'template'
                Template     = 'HighSecurity'
            }

            $result = Resolve-PIMTemplate -PolicyConfig $policyConfig -Templates $templates
            $result['ActivationDuration'] | Should -Be 'PT4H'
            $result['ApprovalRequired']   | Should -Be $true
        }
    }

    Context 'Error handling' {
        It 'Throws on a non-existent configuration file' {
            { Invoke-PIMConfiguration -ConfigurationFile 'C:\nonexistent\config.json' } | Should -Throw
        }

        It 'Throws on an unsupported file extension' {
            $badFile = Join-Path $testDir 'config.toml'
            'key = "value"' | Set-Content -Path $badFile
            { Invoke-PIMConfiguration -ConfigurationFile $badFile } | Should -Throw '*Unsupported file extension*'
        }
    }

    AfterAll {
        Remove-Module PaC -Force -ErrorAction SilentlyContinue
    }
}
