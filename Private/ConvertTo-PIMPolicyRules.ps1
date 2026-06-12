function ConvertTo-PIMPolicyRules {
    <#
    .SYNOPSIS
        Converts simplified PIM policy settings into Microsoft Graph API rule objects.
    .DESCRIPTION
        Internal helper. Maps the human-readable settings hashtable (as defined in
        configuration files) into the array of rule objects required by the
        PATCH /policies/roleManagementPolicies/{id}/rules/{ruleId} endpoint.

        Supported settings keys:
          ActivationDuration            - ISO 8601 duration (e.g. "PT4H")
          ActivationRequirement         - Comma-separated list of enablement rules
                                          (MultiFactorAuthentication, Justification, Ticketing)
          ApprovalRequired              - Boolean
          Approvers                     - Array of @{id; description; [type="user"|"group"]}
          AllowPermanentEligibility     - Boolean
          MaximumEligibilityDuration    - ISO 8601 duration (e.g. "P30D")
          AllowPermanentActivation      - Boolean
          MaximumActivationDuration     - Alias for ActivationDuration when AllowPermanentActivation is used

          Notification_Activation_Alert
          Notification_Activation_Assignee
          Notification_Activation_Admin
          Notification_Eligibility_Alert
          Notification_Eligibility_Assignee
          Notification_Eligibility_Admin

          Each notification block:
            isDefaultRecipientEnabled   - Boolean
            notificationLevel           - "All" or "Critical"
            Recipients                  - Array of email addresses
    .PARAMETER Settings
        The merged settings hashtable to convert.
    .OUTPUTS
        Array of hashtables representing Graph API rule bodies.
    #>
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Settings
    )

    $rules = [System.Collections.Generic.List[hashtable]]::new()

    #region Activation expiration (Expiration_EndUser_Assignment)
    if ($Settings.ContainsKey('ActivationDuration') -or $Settings.ContainsKey('AllowPermanentActivation')) {
        $isExpirationRequired = $true
        $maximumDuration      = $Settings['ActivationDuration'] ?? 'PT8H'

        if ($Settings.ContainsKey('AllowPermanentActivation') -and $Settings['AllowPermanentActivation'] -eq $true) {
            $isExpirationRequired = $false
        }

        $rules.Add(@{
            '@odata.type'        = '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule'
            'id'                 = 'Expiration_EndUser_Assignment'
            'isExpirationRequired' = $isExpirationRequired
            'maximumDuration'    = $maximumDuration
        })
    }
    #endregion

    #region Activation enablement rules (Enablement_EndUser_Assignment)
    if ($Settings.ContainsKey('ActivationRequirement')) {
        $raw          = $Settings['ActivationRequirement']
        $enabledRules = @($raw -split '[,\s]+' | Where-Object { $_ -ne '' })

        $rules.Add(@{
            '@odata.type'  = '#microsoft.graph.unifiedRoleManagementPolicyEnablementRule'
            'id'           = 'Enablement_EndUser_Assignment'
            'enabledRules' = $enabledRules
        })
    }
    #endregion

    #region Approval settings (Approval_EndUser_Assignment)
    if ($Settings.ContainsKey('ApprovalRequired') -or $Settings.ContainsKey('Approvers')) {
        $isApprovalRequired = [bool]($Settings['ApprovalRequired'] ?? $false)
        $approvers          = $Settings['Approvers'] ?? @()

        $primaryApprovers = @($approvers | ForEach-Object {
            $approver = $_
            $approverType = ($approver['type'] ?? 'user').ToLower()
            switch ($approverType) {
                'group' {
                    @{
                        '@odata.type' = '#microsoft.graph.groupMembers'
                        'groupId'     = $approver['id']
                        'description' = $approver['description'] ?? ''
                    }
                }
                default {
                    @{
                        '@odata.type' = '#microsoft.graph.singleUser'
                        'userId'      = $approver['id']
                        'description' = $approver['description'] ?? ''
                    }
                }
            }
        })

        $approvalStages = @()
        if ($isApprovalRequired) {
            $approvalStages = @(
                @{
                    '@odata.type'                    = '#microsoft.graph.unifiedApprovalStage'
                    'approvalStageTimeOutInDays'      = 1
                    'isApproverJustificationRequired' = $true
                    'escalationTimeInMinutes'         = 0
                    'primaryApprovers'               = $primaryApprovers
                    'isEscalationEnabled'            = $false
                    'escalationApprovers'            = @()
                }
            )
        }

        $rules.Add(@{
            '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyApprovalRule'
            'id'          = 'Approval_EndUser_Assignment'
            'setting'     = @{
                '@odata.type'       = '#microsoft.graph.approvalSettings'
                'isApprovalRequired' = $isApprovalRequired
                'isApprovalRequiredForExtension' = $false
                'isRequestorJustificationRequired' = $true
                'approvalMode'      = if ($isApprovalRequired) { 'SingleStage' } else { 'NoApproval' }
                'approvalStages'    = $approvalStages
            }
        })
    }
    #endregion

    #region Eligibility expiration (Expiration_Admin_Eligibility)
    if ($Settings.ContainsKey('MaximumEligibilityDuration') -or $Settings.ContainsKey('AllowPermanentEligibility')) {
        $isExpirationRequired = $true
        $maximumDuration      = $Settings['MaximumEligibilityDuration'] ?? 'P365D'

        if ($Settings.ContainsKey('AllowPermanentEligibility') -and $Settings['AllowPermanentEligibility'] -eq $true) {
            $isExpirationRequired = $false
        }

        $rules.Add(@{
            '@odata.type'          = '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule'
            'id'                   = 'Expiration_Admin_Eligibility'
            'isExpirationRequired' = $isExpirationRequired
            'maximumDuration'      = $maximumDuration
        })
    }
    #endregion

    #region Notification rules
    $notificationMap = @{
        'Notification_Activation_Alert'        = @{ id = 'Notification_Alert_EndUser_Assignment';    recipientType = 'Alert';     notificationType = 'Email' }
        'Notification_Activation_Assignee'     = @{ id = 'Notification_Requestor_EndUser_Assignment'; recipientType = 'Requestor'; notificationType = 'Email' }
        'Notification_Activation_Admin'        = @{ id = 'Notification_Admin_EndUser_Assignment';    recipientType = 'Admin';     notificationType = 'Email' }
        'Notification_Eligibility_Alert'       = @{ id = 'Notification_Alert_Admin_Eligibility';     recipientType = 'Alert';     notificationType = 'Email' }
        'Notification_Eligibility_Assignee'    = @{ id = 'Notification_Requestor_Admin_Eligibility'; recipientType = 'Requestor'; notificationType = 'Email' }
        'Notification_Eligibility_Admin'       = @{ id = 'Notification_Admin_Admin_Eligibility';     recipientType = 'Admin';     notificationType = 'Email' }
    }

    foreach ($settingKey in $notificationMap.Keys) {
        if ($Settings.ContainsKey($settingKey)) {
            $notifSettings = $Settings[$settingKey]
            if ($notifSettings -isnot [hashtable]) {
                $notifSettings = ConvertTo-Hashtable -InputObject $notifSettings
            }
            $meta = $notificationMap[$settingKey]

            $rules.Add(@{
                '@odata.type'                = '#microsoft.graph.unifiedRoleManagementPolicyNotificationRule'
                'id'                         = $meta.id
                'notificationType'           = $meta.notificationType
                'recipientType'              = $meta.recipientType
                'notificationLevel'          = $notifSettings['notificationLevel'] ?? 'All'
                'isDefaultRecipientsEnabled' = [bool]($notifSettings['isDefaultRecipientEnabled'] ?? $true)
                'notificationRecipients'     = @($notifSettings['Recipients'] ?? @())
            })
        }
    }
    #endregion

    return $rules.ToArray()
}
