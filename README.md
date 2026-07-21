# PaC (PIM as Code) — PowerShell Module for Microsoft Privileged Identity Management

PaC (PIM as Code) is a PowerShell module for managing [Microsoft Entra ID Privileged Identity Management (PIM)](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure) at scale using the Microsoft Graph API.

Configure PIM role policies from **JSON or YAML files** with support for **reusable policy templates**, per-role overrides, and full automation pipeline support.

---

## Features

- **Policy templates** — Define a set of PIM settings once, apply to many roles
- **Per-role overrides** — Extend or modify template settings for individual roles
- **JSON & YAML input** — Configuration files in either format
- **Flexible authentication** — Service principal, device code flow, or pre-obtained token
- **Read & inspect** — Retrieve and display current PIM policy settings per role
- **Scale** — Apply settings to multiple roles in a single command
- **WhatIf support** — Preview changes before applying them

---

## Requirements

- PowerShell 7.0 or later
- Microsoft Entra ID with PIM enabled
- One of:
  - Service principal with `RoleManagement.ReadWrite.Directory` permission
  - User account with the Privileged Role Administrator role
- **Optional:** [`powershell-yaml`](https://www.powershellgallery.com/packages/powershell-yaml) module for YAML configuration file support

---

## Installation

```powershell
# Clone the repository
git clone https://github.com/azurekid/PaC.git

# Import the module
Import-Module ./PaC/PaC.psd1
```

---

## Quick Start

### 1. Connect to Microsoft Graph

**Service principal (recommended for automation):**
```powershell
Connect-PIM -TenantId 'contoso.onmicrosoft.com' `
            -ClientId  '00000000-0000-0000-0000-000000000000' `
            -ClientSecret (Read-Host -AsSecureString 'Client secret')
```

**Device code flow (interactive):**
```powershell
Connect-PIM -TenantId 'contoso.onmicrosoft.com' `
            -ClientId  '00000000-0000-0000-0000-000000000000' `
            -DeviceCode
```

**Pre-obtained token (e.g. from Az module or managed identity):**
```powershell
$token = (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com').Token
Connect-PIM -AccessToken $token
```

### 2. Inspect current policy settings

```powershell
# Get simplified policy view
Get-PIMRolePolicy -RoleName 'Security Administrator'

# Get multiple roles at once
Get-PIMRolePolicy -RoleName 'Security Administrator', 'Privileged Role Administrator'

# Get raw Graph API response
Get-PIMRolePolicy -RoleName 'Security Administrator' -Raw
```

### 3. Apply settings to a single role

```powershell
Set-PIMRolePolicy -RoleName 'Security Administrator' -Settings @{
    ActivationDuration         = 'PT4H'
    ActivationRequirement      = 'MultiFactorAuthentication,Justification,Ticketing'
    ApprovalRequired           = $false
    AllowPermanentEligibility  = $false
    MaximumEligibilityDuration = 'P180D'
}
```

### 4. Apply configuration from a file

```powershell
# JSON file
Invoke-PIMConfiguration -ConfigurationFile './Examples/pim-config.json'

# YAML file (requires powershell-yaml module)
Invoke-PIMConfiguration -ConfigurationFile './Examples/pim-config.yml'

# Preview without applying
Invoke-PIMConfiguration -ConfigurationFile './Examples/pim-config.json' -WhatIf
```

---

## Configuration File Format

Configuration files can contain **policy templates**, **role policies**, or both.

### Policy Templates

Define reusable sets of settings under `PolicyTemplates`:

```json
{
  "PolicyTemplates": {
    "HighSecurity": {
      "ActivationDuration": "PT4H",
      "ActivationRequirement": "MultiFactorAuthentication,Justification,Ticketing",
      "ApprovalRequired": true,
      "Approvers": [
        {
          "id": "11111111-2222-3333-4444-555555555555",
          "description": "Privileged Access CAB",
          "type": "group"
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
  }
}
```

### Role Policies

Apply templates or inline settings to specific roles under `EntraRoles.Policies`:

```json
{
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
      },
      {
        "RoleName": "Reports Reader",
        "PolicySource": "inline",
        "Settings": {
          "ActivationDuration": "PT4H",
          "ActivationRequirement": "Justification",
          "ApprovalRequired": false,
          "AllowPermanentEligibility": false,
          "MaximumEligibilityDuration": "P90D"
        }
      }
    ]
  }
}
```

### Separate template file

Templates can be stored in a separate file and referenced via `-TemplateFile`:

```powershell
Invoke-PIMConfiguration -ConfigurationFile './roles.json' -TemplateFile './templates.json'
```

---

## Supported Settings

| Setting | Type | Description |
|---|---|---|
| `ActivationDuration` | ISO 8601 duration | Maximum activation duration (e.g. `PT4H` = 4 hours) |
| `AllowPermanentActivation` | Boolean | If `true`, activations never expire |
| `ActivationRequirement` | Comma-separated string | Requirements at activation time: `MultiFactorAuthentication`, `Justification`, `Ticketing` |
| `ApprovalRequired` | Boolean | Whether approval is required for activation |
| `Approvers` | Array | List of approvers: `@{id; description; [type="user"\|"group"]}` |
| `AllowPermanentEligibility` | Boolean | If `true`, eligibility assignments never expire |
| `MaximumEligibilityDuration` | ISO 8601 duration | Maximum eligibility assignment duration (e.g. `P30D` = 30 days) |
| `Notification_Activation_Alert` | Block | Alert notifications sent when a role is activated |
| `Notification_Activation_Assignee` | Block | Notifications sent to the user who activated |
| `Notification_Activation_Admin` | Block | Notifications sent to admins when a role is activated |
| `Notification_Eligibility_Alert` | Block | Alert notifications for eligibility assignments |
| `Notification_Eligibility_Assignee` | Block | Notifications sent to newly eligible users |
| `Notification_Eligibility_Admin` | Block | Notifications sent to admins for eligibility changes |

**Notification block format:**
```json
{
  "isDefaultRecipientEnabled": true,
  "notificationLevel": "All",
  "Recipients": ["email@contoso.com"]
}
```

---

## Functions

| Function | Description |
|---|---|
| `Connect-PIM` | Connect to Microsoft Graph (service principal, device code, or token) |
| `Disconnect-PIM` | Clear the current session |
| `Get-PIMRoleDefinition` | List or search Entra ID role definitions |
| `Get-PIMRolePolicy` | Get the current PIM policy for one or more roles |
| `Set-PIMRolePolicy` | Apply policy settings to one or more roles |
| `Invoke-PIMConfiguration` | Apply a JSON or YAML configuration file |

---

## Examples

See the [`Examples/`](./Examples/) directory for complete configuration files:

- [`pim-config.json`](./Examples/pim-config.json) — Full JSON example with templates and role configurations
- [`pim-config.yml`](./Examples/pim-config.yml) — Equivalent YAML example

---

## Required Graph API Permissions

| Permission | Type | Required for |
|---|---|---|
| `RoleManagement.Read.Directory` | Application or Delegated | Reading PIM policies |
| `RoleManagement.ReadWrite.Directory` | Application or Delegated | Writing PIM policies |

---

## License

MIT — see [LICENSE](./LICENSE).
