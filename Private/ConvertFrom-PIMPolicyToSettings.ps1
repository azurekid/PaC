function ConvertFrom-PIMPolicyToSettings {
    <#
    .SYNOPSIS
        Converts a simplified PIM policy object into settings hashtable format.
    .DESCRIPTION
        Internal helper used by export/backup workflows to transform
        Get-PIMRolePolicy / Get-PIMGroupPolicy output into the same settings
        schema accepted by Set-PIMRolePolicy / Set-PIMGroupPolicy.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [psobject]$Policy
    )

    $settings = @{}

    if ($null -ne $Policy.ActivationDuration -and $Policy.ActivationDuration -ne '') {
        $settings['ActivationDuration'] = $Policy.ActivationDuration
    }

    if ($null -ne $Policy.AllowPermanentActivation) {
        $settings['AllowPermanentActivation'] = [bool]$Policy.AllowPermanentActivation
    }

    if ($null -ne $Policy.ActivationRequirements -and $Policy.ActivationRequirements -ne '') {
        $settings['ActivationRequirement'] = $Policy.ActivationRequirements
    }

    if ($null -ne $Policy.ApprovalRequired) {
        $settings['ApprovalRequired'] = [bool]$Policy.ApprovalRequired
    }

    if ($Policy.Approvers) {
        $approvers = @()
        foreach ($approver in @($Policy.Approvers)) {
            $entry = @{}
            if ($approver.userId) {
                $entry['id'] = $approver.userId
                $entry['type'] = 'user'
            }
            elseif ($approver.groupId) {
                $entry['id'] = $approver.groupId
                $entry['type'] = 'group'
            }

            if ($approver.description) {
                $entry['description'] = $approver.description
            }

            if ($entry.ContainsKey('id')) {
                $approvers += $entry
            }
        }

        if ($approvers.Count -gt 0) {
            $settings['Approvers'] = $approvers
        }
    }

    if ($null -ne $Policy.MaximumEligibilityDuration -and $Policy.MaximumEligibilityDuration -ne '') {
        $settings['MaximumEligibilityDuration'] = $Policy.MaximumEligibilityDuration
    }

    if ($null -ne $Policy.AllowPermanentEligibility) {
        $settings['AllowPermanentEligibility'] = [bool]$Policy.AllowPermanentEligibility
    }

    $notificationReverseMap = @{
        'Notification_Requestor_EndUser_Assignment' = 'Notification_Activation_Assignee'
        'Notification_Admin_EndUser_Assignment'     = 'Notification_Activation_Admin'
        'Notification_Admin_Admin_Eligibility'      = 'Notification_Eligibility_Admin'
        'Notification_Requestor_Admin_Assignment'   = 'Notification_Assignment_Assignee'
        'Notification_Admin_Admin_Assignment'       = 'Notification_Assignment_Admin'
    }

    if ($Policy.Notifications) {
        foreach ($ruleId in $notificationReverseMap.Keys) {
            $configKey = $notificationReverseMap[$ruleId]
            $notification = $Policy.Notifications[$ruleId]
            if (-not $notification) {
                continue
            }

            $isDefault = $notification.isDefaultRecipientEnabled
            if ($null -eq $isDefault) {
                $isDefault = $notification.isDefaultRecipientsEnabled
            }

            $settings[$configKey] = @{
                isDefaultRecipientEnabled = if ($null -eq $isDefault) { $true } else { [bool]$isDefault }
                notificationLevel         = $notification.notificationLevel ?? 'All'
                Recipients                = @($notification.notificationRecipients ?? @())
            }
        }
    }

    return $settings
}
