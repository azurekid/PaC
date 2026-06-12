#Requires -Modules Pester

Describe 'Resolve-PIMTemplate' {
    BeforeAll {
        # Dot-source the private function under test and its dependency
        $privateDir = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'Private'
        . (Join-Path $privateDir 'Resolve-PIMTemplate.ps1')
    }

    Context 'Template resolution (PolicySource = template)' {
        BeforeAll {
            $templates = @{
                HighSecurity = @{
                    ActivationDuration         = 'PT4H'
                    ActivationRequirement      = 'MultiFactorAuthentication,Justification,Ticketing'
                    ApprovalRequired           = $true
                    AllowPermanentEligibility  = $false
                    MaximumEligibilityDuration = 'P30D'
                }
            }
        }

        It 'Returns template settings when no override is specified' {
            $policy = @{
                RoleName     = 'Security Administrator'
                PolicySource = 'template'
                Template     = 'HighSecurity'
            }
            $result = Resolve-PIMTemplate -PolicyConfig $policy -Templates $templates
            $result['ActivationDuration']         | Should -Be 'PT4H'
            $result['ActivationRequirement']      | Should -Be 'MultiFactorAuthentication,Justification,Ticketing'
            $result['ApprovalRequired']           | Should -Be $true
            $result['AllowPermanentEligibility']  | Should -Be $false
            $result['MaximumEligibilityDuration'] | Should -Be 'P30D'
        }

        It 'Applies scalar overrides over template values' {
            $policy = @{
                RoleName     = 'Reader'
                PolicySource = 'template'
                Template     = 'HighSecurity'
                Override     = @{
                    ActivationDuration    = 'PT2H'
                    ApprovalRequired      = $false
                }
            }
            $result = Resolve-PIMTemplate -PolicyConfig $policy -Templates $templates
            $result['ActivationDuration'] | Should -Be 'PT2H'
            $result['ApprovalRequired']   | Should -Be $false
            # Non-overridden values should remain from template
            $result['MaximumEligibilityDuration'] | Should -Be 'P30D'
        }

        It 'Merges nested hashtable overrides (e.g. notification blocks)' {
            $templatesWithNotif = @{
                Base = @{
                    ActivationDuration         = 'PT8H'
                    Notification_Activation_Alert = @{
                        isDefaultRecipientEnabled = $true
                        notificationLevel         = 'All'
                        Recipients                = @('admin@contoso.com')
                    }
                }
            }
            $policy = @{
                RoleName     = 'Reader'
                PolicySource = 'template'
                Template     = 'Base'
                Override     = @{
                    Notification_Activation_Alert = @{
                        notificationLevel = 'Critical'
                        Recipients        = @('soc@contoso.com')
                    }
                }
            }
            $result = Resolve-PIMTemplate -PolicyConfig $policy -Templates $templatesWithNotif
            $notif = $result['Notification_Activation_Alert']
            $notif['notificationLevel']         | Should -Be 'Critical'
            $notif['Recipients']                | Should -Contain 'soc@contoso.com'
            # isDefaultRecipientEnabled comes from template, not overridden
            $notif['isDefaultRecipientEnabled'] | Should -Be $true
        }

        It 'Does not mutate the original template' {
            $policy = @{
                RoleName     = 'Test Role'
                PolicySource = 'template'
                Template     = 'HighSecurity'
                Override     = @{ ActivationDuration = 'PT1H' }
            }
            $before = $templates['HighSecurity']['ActivationDuration']
            Resolve-PIMTemplate -PolicyConfig $policy -Templates $templates | Out-Null
            $templates['HighSecurity']['ActivationDuration'] | Should -Be $before
        }

        It 'Throws when the template name is not found' {
            $policy = @{
                RoleName     = 'Role'
                PolicySource = 'template'
                Template     = 'NonExistent'
            }
            { Resolve-PIMTemplate -PolicyConfig $policy -Templates $templates } | Should -Throw
        }

        It 'Throws when template name is missing' {
            $policy = @{
                RoleName     = 'Role'
                PolicySource = 'template'
            }
            { Resolve-PIMTemplate -PolicyConfig $policy -Templates $templates } | Should -Throw
        }
    }

    Context 'Inline resolution (PolicySource = inline)' {
        It 'Returns the inline settings directly' {
            $policy = @{
                RoleName     = 'Reader'
                PolicySource = 'inline'
                Settings     = @{
                    ActivationDuration = 'PT2H'
                    ApprovalRequired   = $false
                }
            }
            $result = Resolve-PIMTemplate -PolicyConfig $policy
            $result['ActivationDuration'] | Should -Be 'PT2H'
            $result['ApprovalRequired']   | Should -Be $false
        }

        It 'Throws when Settings block is missing' {
            $policy = @{
                RoleName     = 'Reader'
                PolicySource = 'inline'
            }
            { Resolve-PIMTemplate -PolicyConfig $policy } | Should -Throw
        }
    }

    Context 'Default PolicySource behaviour' {
        It 'Defaults to inline when PolicySource is omitted' {
            $policy = @{
                RoleName = 'Reader'
                Settings = @{ ActivationDuration = 'PT1H' }
            }
            $result = Resolve-PIMTemplate -PolicyConfig $policy
            $result['ActivationDuration'] | Should -Be 'PT1H'
        }
    }

    Context 'Unknown PolicySource' {
        It 'Throws for an unknown PolicySource value' {
            $policy = @{
                RoleName     = 'Reader'
                PolicySource = 'unknown'
            }
            { Resolve-PIMTemplate -PolicyConfig $policy } | Should -Throw
        }
    }
}
