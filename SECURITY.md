# Security Policy

## Supported Version

Security fixes are applied to the latest version on the `main` branch.

## Reporting a Vulnerability

Use GitHub private vulnerability reporting from the repository's **Security** tab when available.

Do not include real email files, attachments, addresses, message headers, credentials, or other sensitive information in a public issue. Include the affected version, reproduction steps using safe sample data, expected behavior, actual behavior, and potential impact.

## Security Model

PhishFry is designed for local, read-only inspection of a manually selected `.eml` file.

The script:

- accepts `.eml` files up to 50 MB
- does not make network requests or send analysis data elsewhere
- does not request or store credentials
- does not open URLs or execute attachment content
- decodes supported MIME content in memory and does not extract attachments to disk
- writes only to the Windows clipboard when the user clicks a copy button

## Important Limitations

SPF, DKIM, and DMARC results are read from message headers and are not independently verified. Email headers can be malformed or forged, and the oldest `Received` entry is investigative evidence rather than proof of the sender's identity.

Attachment hashes are identifiers, not malware verdicts. PhishFry is not a sandbox, antivirus product, URL reputation service, or complete forensic suite.

## Operational Guidance

Run a trusted copy of the script on a supported Windows system. Treat email contents, parsed metadata, attachment hashes, and clipboard values as potentially sensitive evidence and handle them according to your organization's requirements.
