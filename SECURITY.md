# Security policy

## Reporting a vulnerability
Please use GitHub's private reporting: the **Security** tab of this repository, then **Report a vulnerability**. Do not post details in a public issue.

We will acknowledge a report within 3 business days and keep you informed until it is fixed. We credit reporters who want credit.

## What is in scope
- The MCP server (`server.js`) and its tools, including the code scanner and the live lookup tools.
- The skills content, if a recommendation in it would make software less secure.
- The release pipeline (`.github/`).

## Design notes useful to reviewers
- The server makes no LLM calls. Its only network calls are read-only queries to cisa.gov, nvd.nist.gov and api.osv.dev, made when you call those tools.
- Text returned from those feeds is labelled untrusted in the tool output.
- `scan_path` is read-only, skips symlinks and `.env*` files, and hides source lines by default so secrets are not echoed.
- Sponsor notes appended to some tool output are plain text, labelled as non-instructions, and can be removed with `BULWARK_NO_PROMO=1`.

## Supported versions
The latest release.
