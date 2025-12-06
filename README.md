# PowerShell Admin Toolkit

Production-ready PowerShell reference for managed service providers and Windows system administrators. Covers Microsoft 365, Exchange Online, Microsoft Graph, Active Directory, Entra ID, Windows Server, and security hardening.

## Installation

Copy the `powershell-admin-toolkit` folder to your Claude skills directory or reference directly.

## Structure

```
powershell-admin-toolkit/
├── SKILL.md                          # Main skill file with core patterns
├── README.md                         # This file
└── references/
    ├── active-directory.md           # On-prem AD administration
    ├── microsoft-graph.md            # MS Graph API for M365 automation
    ├── exchange-online.md            # Exchange Online management
    ├── entra-id.md                   # Azure AD/Entra ID operations
    ├── windows-server.md             # Server roles, services, storage
    ├── security-hardening.md         # BitLocker, Defender, certificates
    ├── remote-management.md          # WinRM, remote execution
    └── msp-operations.md             # Multi-tenant, onboarding, reporting
```

## Coverage

### Microsoft 365
- Microsoft Graph API (delegated and app-only auth)
- Exchange Online (mailboxes, permissions, transport rules, compliance)
- Entra ID (users, groups, licensing, conditional access)
- Teams and SharePoint administration

### On-Premises
- Active Directory (users, groups, computers, GPO, replication)
- Windows Server (services, storage, events, clustering)
- Hyper-V, IIS, SQL Server management

### Security
- BitLocker encryption
- Windows Defender configuration
- Certificate management
- Audit policies and hardening

### MSP Operations
- Multi-tenant management patterns
- User onboarding/offboarding workflows
- Automated reporting
- RMM integration patterns

## Requirements

- PowerShell 5.1+ (PowerShell 7+ recommended)
- Microsoft.Graph module for M365 operations
- ExchangeOnlineManagement module for Exchange
- ActiveDirectory module (RSAT) for on-prem AD
- Appropriate admin permissions per task

## Usage

Reference the appropriate file based on task:

| Task | Reference File |
|------|----------------|
| M365 user/group management | `microsoft-graph.md` |
| Mailbox operations | `exchange-online.md` |
| On-prem AD administration | `active-directory.md` |
| Azure AD/Entra ID | `entra-id.md` |
| Server management | `windows-server.md` |
| Security configuration | `security-hardening.md` |
| Remote administration | `remote-management.md` |
| Multi-tenant operations | `msp-operations.md` |

## Notes

- All scripts are designed for production use with minimal modification
- Replace placeholder values (domain.com, SERVER01, etc.) with actual values
- Test in non-production environments first
- App-only authentication recommended for unattended scripts
- Credentials should be stored securely (Azure Key Vault, Windows Credential Manager)

## License

MIT
---
Maintained by [RainCity Techworks](https://rain-city.tech) | Seattle MSP
