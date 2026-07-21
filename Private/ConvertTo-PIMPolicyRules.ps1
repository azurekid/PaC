function ConvertTo-PIMPolicyRules {
    <#
    .SYNOPSIS
        Converts simplified PIM policy settings into Microsoft Graph API rule objects.
    .DESCRIPTION
        Internal helper. Maps the human-readable settings hashtable (as defined in
        configuration files) into the array of rule objects required by the
        PATCH /policies/roleManagementPolicies/{id}/rules/{ruleId} endpoint.

        Supported settings keys:

          -- Activation (EndUser_Assignment) --
          ActivationDuration            - ISO 8601 duration (e.g. "PT4H")
          AllowPermanentActivation      - Boolean; disables expiration when true
          ActivationRequirement         - Comma-separated enablement rules
                                          (MultiFactorAuthentication, Justification, Ticketing)
          ApprovalRequired              - Boolean
          Approvers                     - Array of @{id; description; [type="user"|"group"]}

          -- Eligible assignment (Admin_Eligibility) --
          AllowPermanentEligibility     - Boolean; disables expiration when true
          MaximumEligibilityDuration    - ISO 8601 duration (e.g. "P30D")

          -- Active assignment (Admin_Assignment) --
          AllowPermanentActiveAssignment    - Boolean; disables expiration when true
          MaximumActiveAssignmentDuration   - ISO 8601 duration (e.g. "P15D")
          ActiveAssignmentRequirement       - Comma-separated enablement rules
                                             (MultiFactorAuthentication, Justification)

          -- Notifications (Entra ID only supports Admin and Requestor; Alert is Azure RBAC only) --
          Notification_Activation_Assignee   (EndUser_Assignment / Requestor)
          Notification_Activation_Admin      (EndUser_Assignment / Admin)
          Notification_Eligibility_Admin     (Admin_Eligibility / Admin)
          Notification_Assignment_Assignee   (Admin_Assignment / Requestor)
          Notification_Assignment_Admin      (Admin_Assignment / Admin)

          Each notification block:
            isDefaultRecipientEnabled   - Boolean
            notificationLevel           - "All" or "Critical"
            Recipients                  - Array of email addresses
                                          (ignored when isDefaultRecipientEnabled is true)
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

    #region Active assignment expiration (Expiration_Admin_Assignment)
    if ($Settings.ContainsKey('MaximumActiveAssignmentDuration') -or $Settings.ContainsKey('AllowPermanentActiveAssignment')) {
        $isExpirationRequired = $true
        $maximumDuration      = $Settings['MaximumActiveAssignmentDuration'] ?? 'P180D'

        if ($Settings.ContainsKey('AllowPermanentActiveAssignment') -and $Settings['AllowPermanentActiveAssignment'] -eq $true) {
            $isExpirationRequired = $false
        }

        $rules.Add(@{
            '@odata.type'          = '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule'
            'id'                   = 'Expiration_Admin_Assignment'
            'isExpirationRequired' = $isExpirationRequired
            'maximumDuration'      = $maximumDuration
        })
    }
    #endregion

    #region Active assignment enablement (Enablement_Admin_Assignment)
    if ($Settings.ContainsKey('ActiveAssignmentRequirement')) {
        $raw          = $Settings['ActiveAssignmentRequirement']
        $enabledRules = @($raw -split '[,\s]+' | Where-Object { $_ -ne '' })

        $rules.Add(@{
            '@odata.type'  = '#microsoft.graph.unifiedRoleManagementPolicyEnablementRule'
            'id'           = 'Enablement_Admin_Assignment'
            'enabledRules' = $enabledRules
        })
    }
    #endregion

    #region Notification rules
    # Note: Entra ID role policies only support "Admin" and "Requestor" recipient types.
    # "Alert" recipient type is NOT valid for Entra ID (only for Azure RBAC).
    # Notification_Alert_Admin_Eligibility and Notification_Alert_Admin_Assignment are also invalid for Entra ID.
    $notificationMap = @{
        'Notification_Activation_Assignee'  = @{ id = 'Notification_Requestor_EndUser_Assignment'; recipientType = 'Requestor'; notificationType = 'Email'; targetCaller = 'EndUser'; targetLevel = 'Assignment' }
        'Notification_Activation_Admin'     = @{ id = 'Notification_Admin_EndUser_Assignment';     recipientType = 'Admin';     notificationType = 'Email'; targetCaller = 'EndUser'; targetLevel = 'Assignment' }
        'Notification_Eligibility_Admin'    = @{ id = 'Notification_Admin_Admin_Eligibility';      recipientType = 'Admin';     notificationType = 'Email'; targetCaller = 'Admin';   targetLevel = 'Eligibility' }
        'Notification_Assignment_Assignee'  = @{ id = 'Notification_Requestor_Admin_Assignment';   recipientType = 'Requestor'; notificationType = 'Email'; targetCaller = 'Admin';   targetLevel = 'Assignment' }
        'Notification_Assignment_Admin'     = @{ id = 'Notification_Admin_Admin_Assignment';       recipientType = 'Admin';     notificationType = 'Email'; targetCaller = 'Admin';   targetLevel = 'Assignment' }
    }

    foreach ($settingKey in $notificationMap.Keys) {
        if ($Settings.ContainsKey($settingKey)) {
            $notifSettings = $Settings[$settingKey]
            if ($notifSettings -isnot [hashtable]) {
                $notifSettings = ConvertTo-Hashtable -InputObject $notifSettings
            }
            $meta = $notificationMap[$settingKey]

            $isDefaultRecipientsEnabled = [bool]($notifSettings['isDefaultRecipientEnabled'] ?? $true)
            $recipients = @($notifSettings['Recipients'] ?? @())

            # Graph doesn't allow both isDefaultRecipientsEnabled=true and custom recipients.
            # When using default recipients, clear the custom recipients array.
            if ($isDefaultRecipientsEnabled -eq $true) {
                $recipients = @()
            }

            $rules.Add(@{
                '@odata.type'                = '#microsoft.graph.unifiedRoleManagementPolicyNotificationRule'
                'id'                         = $meta.id
                'notificationType'           = $meta.notificationType
                'recipientType'              = $meta.recipientType
                'notificationLevel'          = $notifSettings['notificationLevel'] ?? 'All'
                'isDefaultRecipientsEnabled' = $isDefaultRecipientsEnabled
                'notificationRecipients'     = $recipients
                'target'                     = @{
                    'caller'              = $meta.targetCaller
                    'operations'          = @('All')
                    'level'               = $meta.targetLevel
                    'inheritableSettings' = @()
                    'enforcedSettings'    = @()
                }
            })
        }
    }
    #endregion

    return $rules.ToArray()
}
