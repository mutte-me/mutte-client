# Security policy

## Supported versions

Mutte is alpha software. Only the current `main` revision and the newest
prerelease receive security fixes. Older commits, client archives, protocol
alphas, and relay images are unsupported.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's
**Security → Report a vulnerability** flow in the public
`yuramelesh/mutte-client` repository so the report and follow-up remain private.
If that control is unavailable, contact the maintainer through their GitHub
profile without including sensitive details and request a private channel.

Include the affected version or commit, impact, reproduction steps, and any
suggested mitigation. Never include production credentials, private keys,
access tokens, real message content, or another person's personal data.

Relevant findings include cryptographic or MLS state errors, authentication or
authorization bypasses, secret leakage, unsafe local-vault behavior, malicious
wire-payload handling, attachment access violations, and release-pipeline or
update integrity problems.

There is currently no bug-bounty program. Please allow time for validation and
coordinated remediation before publishing details.
