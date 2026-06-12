#Requires -Modules Pester

Describe 'ConvertTo-PIMPolicyRules' {
    BeforeAll {
        $privateDir = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'Private'
        . (Join-Path $privateDir 'ConvertTo-PIMPolicyRules.ps1')
        . (Join-Path $privateDir 'Resolve-PIMTemplate.ps1')  # ConvertTo-Hashtable dependency
    }

    Context 'Activation duration (Expiration_EndUser_Assignment)' {
        It 'Generates an expiration rule with the correct duration' {
            $rules = ConvertTo-PIMPolicyRules -Settings @{ ActivationDuration = 'PT4H' }
            $rule  = $rules | Where-Object { $_['id'] -eq 'Expiration_EndUser_Assignment' }
            $rule                          | Should -Not -BeNullOrEmpty
            $rule['isExpirationRequired']  | Should -Be $true
            $rule['maximumDuration']       | Should -Be 'PT4H'
        }

        It 'Sets isExpirationRequired to false when AllowPermanentActivation is true' {
            $rules = ConvertTo-PIMPolicyRules -Settings @{
                AllowPermanentActivation = $true
                ActivationDuration       = 'PT8H'
            }
            $rule = $rules | Where-Object { $_['id'] -eq 'Expiration_EndUser_Assignment' }
            $rule['isExpirationRequired'] | Should -Be $false
        }

        It 'Does not generate an expiration rule when no duration-related key is present' {
            $rules = ConvertTo-PIMPolicyRules -Settings @{ ApprovalRequired = $false }
            $rule  = $rules | Where-Object { $_['id'] -eq 'Expiration_EndUser_Assignment' }
            $rule | Should -BeNullOrEmpty
        }
    }

    Context 'Activation enablement (Enablement_EndUser_Assignment)' {
        It 'Parses a comma-separated ActivationRequirement string' {
            $rules = ConvertTo-PIMPolicyRules -Settings @{
                ActivationRequirement = 'MultiFactorAuthentication,Justification,Ticketing'
            }
            $rule = $rules | Where-Object { $_['id'] -eq 'Enablement_EndUser_Assignment' }
            $rule                   | Should -Not -BeNullOrEmpty
            $rule['enabledRules']   | Should -Contain 'MultiFactorAuthentication'
            $rule['enabledRules']   | Should -Contain 'Justification'
            $rule['enabledRules']   | Should -Contain 'Ticketing'
        }

        It 'Handles a single requirement without a comma' {
            $rules = ConvertTo-PIMPolicyRules -Settings @{ ActivationRequirement = 'Justification' }
            $rule  = $rules | Where-Object { $_['id'] -eq 'Enablement_EndUser_Assignment' }
            $rule['enabledRules'] | Should -HaveCount 1
            $rule['enabledRules'] | Should -Contain 'Justification'
        }
    }

    Context 'Approval (Approval_EndUser_Assignment)' {
        It 'Sets approval as required with a single user approver' {
            $rules = ConvertTo-PIMPolicyRules -Settings @{
                ApprovalRequired = $true
                Approvers        = @(@{ id = 'aaaa-bbbb'; description = 'CAB Lead' })
            }
            $rule = $rules | Where-Object { $_['id'] -eq 'Approval_EndUser_Assignment' }
            $rule                                      | Should -Not -BeNullOrEmpty
            $rule['setting']['isApprovalRequired']     | Should -Be $true
            $rule['setting']['approvalMode']           | Should -Be 'SingleStage'
            $primaryApprovers = $rule['setting']['approvalStages'][0]['primaryApprovers']
            $primaryApprovers[0]['@odata.type']        | Should -Be '#microsoft.graph.singleUser'
            $primaryApprovers[0]['userId']             | Should -Be 'aaaa-bbbb'
        }

        It 'Maps a group-type approver to groupMembers' {
            $rules = ConvertTo-PIMPolicyRules -Settings @{
                ApprovalRequired = $true
                Approvers        = @(@{ id = 'gggg-hhhh'; description = 'CAB Group'; type = 'group' })
            }
            $rule             = $rules | Where-Object { $_['id'] -eq 'Approval_EndUser_Assignment' }
            $primaryApprovers = $rule['setting']['approvalStages'][0]['primaryApprovers']
            $primaryApprovers[0]['@odata.type'] | Should -Be '#microsoft.graph.groupMembers'
            $primaryApprovers[0]['groupId']     | Should -Be 'gggg-hhhh'
        }

        It 'Sets approvalMode to NoApproval when ApprovalRequired is false' {
            $rules = ConvertTo-PIMPolicyRules -Settings @{ ApprovalRequired = $false }
            $rule  = $rules | Where-Object { $_['id'] -eq 'Approval_EndUser_Assignment' }
            $rule['setting']['isApprovalRequired'] | Should -Be $false
            $rule['setting']['approvalMode']       | Should -Be 'NoApproval'
        }
    }

    Context 'Eligibility expiration (Expiration_Admin_Eligibility)' {
        It 'Generates an eligibility expiration rule' {
            $rules = ConvertTo-PIMPolicyRules -Settings @{
                AllowPermanentEligibility  = $false
                MaximumEligibilityDuration = 'P30D'
            }
            $rule = $rules | Where-Object { $_['id'] -eq 'Expiration_Admin_Eligibility' }
            $rule                          | Should -Not -BeNullOrEmpty
            $rule['isExpirationRequired']  | Should -Be $true
            $rule['maximumDuration']       | Should -Be 'P30D'
        }

        It 'Disables expiration when AllowPermanentEligibility is true' {
            $rules = ConvertTo-PIMPolicyRules -Settings @{ AllowPermanentEligibility = $true }
            $rule  = $rules | Where-Object { $_['id'] -eq 'Expiration_Admin_Eligibility' }
            $rule['isExpirationRequired'] | Should -Be $false
        }
    }

    Context 'Notification rules' {
        It 'Generates a notification rule for Notification_Activation_Alert' {
            $rules = ConvertTo-PIMPolicyRules -Settings @{
                Notification_Activation_Alert = @{
                    isDefaultRecipientEnabled = $true
                    notificationLevel         = 'All'
                    Recipients                = @('soc-alerts@contoso.com')
                }
            }
            $rule = $rules | Where-Object { $_['id'] -eq 'Notification_Alert_EndUser_Assignment' }
            $rule                              | Should -Not -BeNullOrEmpty
            $rule['notificationLevel']         | Should -Be 'All'
            $rule['isDefaultRecipientsEnabled'] | Should -Be $true
            $rule['notificationRecipients']    | Should -Contain 'soc-alerts@contoso.com'
        }

        It 'Generates a notification rule for Notification_Eligibility_Admin' {
            $rules = ConvertTo-PIMPolicyRules -Settings @{
                Notification_Eligibility_Admin = @{
                    isDefaultRecipientEnabled = $false
                    notificationLevel         = 'Critical'
                    Recipients                = @('admin@contoso.com')
                }
            }
            $rule = $rules | Where-Object { $_['id'] -eq 'Notification_Admin_Admin_Eligibility' }
            $rule                             | Should -Not -BeNullOrEmpty
            $rule['notificationLevel']        | Should -Be 'Critical'
            $rule['isDefaultRecipientsEnabled'] | Should -Be $false
        }
    }

    Context 'Empty settings' {
        It 'Returns an empty array when no known settings keys are present' {
            $rules = ConvertTo-PIMPolicyRules -Settings @{ UnknownKey = 'value' }
            $rules | Should -HaveCount 0
        }
    }

    Context 'Full settings block' {
        It 'Generates all expected rules for a complete HighSecurity-style settings block' {
            $settings = @{
                ActivationDuration         = 'PT4H'
                ActivationRequirement      = 'MultiFactorAuthentication,Justification,Ticketing'
                ApprovalRequired           = $true
                Approvers                  = @(@{ id = '11111111-2222-3333-4444-555555555555'; description = 'CAB' })
                AllowPermanentEligibility  = $false
                MaximumEligibilityDuration = 'P30D'
                Notification_Activation_Alert = @{
                    isDefaultRecipientEnabled = $true
                    notificationLevel         = 'All'
                    Recipients                = @('soc-alerts@contoso.com')
                }
            }
            $rules = ConvertTo-PIMPolicyRules -Settings $settings
            $ruleIds = $rules | ForEach-Object { $_['id'] }
            $ruleIds | Should -Contain 'Expiration_EndUser_Assignment'
            $ruleIds | Should -Contain 'Enablement_EndUser_Assignment'
            $ruleIds | Should -Contain 'Approval_EndUser_Assignment'
            $ruleIds | Should -Contain 'Expiration_Admin_Eligibility'
            $ruleIds | Should -Contain 'Notification_Alert_EndUser_Assignment'
        }
    }
}
