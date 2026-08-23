# PhishFry

A local PowerShell utility for inspecting evidence contained in `.eml` email files.

![PhishFry interface](assets/phishfry-gui.png)

---

PhishFry is one Windows PowerShell 5.1 script with a WPF interface. It reads a selected email file and presents useful message, sender, authentication, URL, and attachment evidence in one place for review or copying.

The analysis stays on the local computer. The script does not contact external services, open URLs, or execute attachments.

## Quick Start

You need Windows PowerShell 5.1 on Windows. No additional modules are required.

```powershell
git clone https://github.com/delriscotechnologies/phishfry.git
cd phishfry
powershell.exe -File .\PhishFry.ps1
```

Choose an `.eml` file, select **Analyze**, and review the results. Files larger than 50 MB are rejected.

If your organization restricts PowerShell execution, follow its approved execution-policy and code-signing requirements.

## What You Get

| Section | Evidence shown |
|---|---|
| Overview | Subject, date, From, To, and Cc |
| Reported Authentication | SPF, DKIM, and DMARC results reported in the message headers |
| Sender Evidence | From and Sender domains, Return-Path, Reply-To, and the oldest `Received` host and IP |
| URLs | Unique HTTP and HTTPS URLs found in decoded text and HTML message parts |
| Attachments | Filename, content type, decoded size, and SHA-256 hash |

Copy buttons copy individual evidence values to the Windows clipboard.

## How Analysis Works

PhishFry reads the selected `.eml` file into memory, parses its headers and MIME structure, decodes supported Base64 and quoted-printable content, extracts URLs, and calculates attachment hashes. Attachments are not written to disk.

## Safety and Limitations

- Analysis is local and read-only; the selected `.eml` file is not modified.
- URLs and attachments are displayed as evidence but are never opened or executed.
- SPF, DKIM, and DMARC values are reported from existing email headers. PhishFry does not independently perform DNS lookups or cryptographic verification.
- Header values can be forged. Sender and routing fields are evidence for investigation, not proof of identity.
- A SHA-256 hash identifies attachment content; it does not determine whether the attachment is safe.
- PhishFry does not provide a phishing, malware, or reputation verdict.

See [SECURITY.md](SECURITY.md) for security and vulnerability-reporting guidance.

## License

PhishFry is available under the [MIT License](LICENSE).
