# Contributing to Bulwark

Thank you. Bulwark is Apache-2.0 and maintained by ZagAIrot.

## How we know who changed what
- Every change comes in as a pull request; `main` is protected and nothing is pushed to it directly.
- Every commit must carry a sign-off line (`git commit -s`), the Developer Certificate of Origin: you wrote it, or have the right to submit it, under this project's license.
- `CODEOWNERS` routes every file to a named maintainer for review. Security-relevant files (`server.js`, `skills/`, `.github/`) need a maintainer's approval.
- CI runs the full test suite on every pull request. Third-party actions are pinned to full commit hashes.

## What you grant by contributing
By submitting a contribution you agree that:
1. It is licensed to everyone under the Apache License 2.0 (this project's license), as Section 5 of that license says.
2. You also grant ZagAIrot a perpetual, worldwide, non-exclusive, royalty-free, irrevocable right to use, modify, sublicense and **relicense** your contribution, including under other terms, so the project can change its license in future. You keep your own copyright.
3. You have the right to make this grant (it is not your employer's code unless they agree, and it contains no one else's secrets or personal data).

If you are not comfortable with point 2, please open an issue instead of a pull request.

## Adding or changing a skill
Skills are Markdown files in `skills/` with a header (`name`, `description`, `tags`). Rules:
- Cite a primary source (standard, vendor advisory, paper) for any factual claim that is new or time-sensitive.
- No invented statistics. If you are unsure, say so.
- No vendor marketing. Tools are recommended on their technical merit and license.
- Run `npm test` before opening the pull request.

## Reporting security problems
See [SECURITY.md](SECURITY.md). Please do not open a public issue for a vulnerability.
