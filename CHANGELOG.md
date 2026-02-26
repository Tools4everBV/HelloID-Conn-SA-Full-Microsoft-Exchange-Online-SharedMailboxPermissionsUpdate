# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

## [2.0.0.0] - 2025-02-26

### Added
- Certificate-based authentication support for Microsoft Entra ID and Exchange Online
- Dual list interface for managing user permissions with visual separation of available users and assigned users
- Support for three permission types: Full Access, Send As, and Send on Behalf
- Microsoft Graph API integration for user object retrieval to optimize performance
- Wildcard search functionality for shared mailbox discovery (by name and email addresses)
- Comprehensive permission management with grant and revoke operations
- Enhanced error handling with detailed audit logging for all permission changes
- Performance optimization strategy prioritizing Graph API over Exchange Online cmdlets where possible
- Detailed README with setup instructions, permission management workflow, and API documentation

### Changed
- **BREAKING**: Migrated authentication from secret-based to certificate-based authentication
  - Old variables: `EntraSecret`, `EntraTenantId`, `EntraAppID`, `EntraOrganization`
  - New variables: `EntraIdCertificateBase64String`, `EntraIdCertificatePassword`, `EntraIdOrganization`, `EntraIdAppId`, `EntraIdTenantId`
- **Performance**: Implemented hybrid approach using Graph API for user object retrieval while leveraging Exchange Online cmdlets for permission operations
- Global variable naming convention updated to `EntraId` prefix for consistency
- Form structure redesigned with improved dual list interface for permission management
- Data sources refactored:
  - `EXO-Get-Shared-Mailboxes-Wildcard-Name-EmailAddresses` - Optimized shared mailbox search using `Get-EXORecipient`
  - `mailbox-generate-table-sharedmailbox-left` - User listing via Microsoft Graph API
  - `mailbox-generate-table-sharedmailbox-right` - Permission assignment retrieval from Exchange Online with Graph API user enrichment
- Exchange Online module updated to latest version for improved reliability and performance
- Error messages enhanced with better context and troubleshooting information
- Audit logging structure improved for better compliance and troubleshooting

### Removed
- Legacy authentication method using client secret
- Old global variable structure
- Hardcoded permission management logic

### Fixed
- Improved permission retrieval performance by combining Exchange Online cmdlets with Graph API user object enrichment
- Enhanced error handling for permission operations with detailed exception context
- Better handling of special characters in search values during mailbox discovery

## [1.0.0.0] - 2021-04-29

### Added
- Initial release of HelloID-Conn-SA-Full-Exchange-Online-MailboxPermissionsUpdate
- Shared mailbox permission management functionality in Exchange Online
- Form-based permission management workflow
- Support for Full Access, Send As, and Send on Behalf permission types
- Dual list interface for adding and removing user permissions
- Basic Exchange Online cmdlet integration for permission management
