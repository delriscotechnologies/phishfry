<p align="center">
  <img src="assets/phishfry-logo.png" alt="PhishFry" width="420">
</p>

<p align="center">
  Local EML evidence analysis for email security and forensic review.
</p>

---

PhishFry is a PowerShell utility for inspecting evidence contained in EML files. It presents message headers, reported authentication results, sender evidence, URLs, and attachment hashes in a simple WPF interface.

The parser runs locally and does not contact external analysis services, open URLs, or execute attachments. The file picker is a Windows dialog: browsing a network location can contact that location before script validation. UNC paths, mapped network drives, and detected reparse points are rejected for analysis; copy the EML to a local drive first.

> PhishFry analyzes supported EML and MIME structures stored locally. Nothing is uploaded.

## Install

You need Windows and PowerShell 5.1 or newer. No additional modules are required.

```powershell
git clone https://github.com/delriscotechnologies/phishfry.git
cd phishfry
powershell.exe -File .\PhishFry.ps1
```

Choose an .eml file, select **Analyze**, and review the results. Files larger than 50 MB are rejected.

If your organization restricts PowerShell execution, follow its approved execution policy and code-signing requirements.

## What it does

1. Reads the selected .eml file into memory and parses its headers and MIME structure.
2. Decodes supported Base64 and quoted-printable content.
3. Extracts HTTP/HTTPS strings and HTML `href`, `src`, and `action` attributes, decoding HTML entities without rendering HTML.
4. Calculates SHA-256 hashes for attachments without writing them to disk.

## Output

| Section | Evidence shown |
| --- | --- |
| Overview | Subject, date, From, To, and Cc |
| Reported Authentication | SPF, DKIM, and DMARC results reported in the message headers |
| Sender Evidence | From and Sender domains, Return-Path, Reply-To, and the oldest `Received` host and IP |
| URLs | Unique HTTP and HTTPS URLs found in decoded text and HTML message parts |
| Attachments | Filename, content type, decoded size, and SHA-256 hash |

Copy buttons copy individual evidence values to the Windows clipboard.

## Demo

![PhishFry interface](assets/phishfry-gui.png)

## Scope and limits

- PhishFry is intended for safe, local triage of .eml files without interacting with potentially malicious content.
- URLs, IP addresses, sender information, and attachment hashes are extracted as evidence for approved investigation workflows.
- URLs are never opened, and attachments are never executed by PhishFry.
- SPF, DKIM, and DMARC values are reported from existing email headers and are not independently verified.
- SHA-256 hashes can be used to investigate attachments without opening them, but a hash alone does not determine whether a file is safe.
- Attachment hashes cover the decoded attachment bytes; only the MIME boundary's framing newline is removed.
- Contradictory authentication results show `Conflicting`; unrecognized syntax shows `Unrecognized`. Multiple or invalid sender mailboxes show `Decode failed` instead of selecting a domain arbitrarily.
- Missing multipart boundaries, excessive nesting, unsupported embedded messages, and undecodable text abort analysis with an error. No partial result is retained for those failures. Attachment transfer-decoding failures remain visible in their rows.
- Input is limited to 50 MiB, MIME nesting to 30 levels, and MIME entity count to 10,000. File size is also checked on the open read handle. These limits do not guarantee a particular runtime or memory footprint.
- URL extraction is lexical, not a complete HTML parser. It preserves URL punctuation and does not resolve relative URLs, execute JavaScript, parse CSS semantics, or fetch external content. Plain-text sentence punctuation can be included in a candidate URL.
- Analysis runs synchronously. Windows/WPF responsiveness and peak memory have not been measured.
- Local-path checks reduce accidental remote reads; they do not make the Windows picker offline or eliminate path-replacement races.

See [SECURITY.md](SECURITY.md) for security and vulnerability-reporting guidance.

## License

PhishFry is available under the [MIT License](LICENSE).
