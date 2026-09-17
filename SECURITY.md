# Security Policy

PRISM is a security auditing tool. If it has a vulnerability, that is a
credibility problem first and a bug second — please report it privately,
not as a public issue.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository:
[github.com/picaro10/prism/security/advisories/new](https://github.com/picaro10/prism/security/advisories/new).
This opens a draft security advisory visible only to the maintainer until a
fix ships — it does not create a public issue or notify anyone else.

If that path is ever unavailable, open a regular issue asking for a private
contact channel; do not post exploit details or affected-project specifics
in a public issue or PR.

Please include:
- The PRISM version (`prism --version`) and how you ran it (CLI flags, or
  which entry point if using it as a library).
- A minimal reproduction — ideally a small project/fixture that triggers the
  issue, not a link to a private/proprietary codebase.
- What you'd expect PRISM to do instead (fail closed, refuse the input,
  not execute, etc.).

## Scope

In scope: anything that lets an audited project's content (files, a crafted
report JSON, a crafted git repo, or a crafted `.zip`) cause PRISM to execute
unintended code, read/write outside the confined project root, or silently
under-report a real risk as clean. `src/core/input.ts`, `src/utils/git-safe.ts`,
`src/utils/safe-read.ts`, and `src/dashboard/server.ts` are the modules that
carry that trust boundary.

Out of scope: findings in PRISM's own audit output about a *third-party*
project you scanned — that's the tool working, not a vulnerability in it.

## Response

This project has one maintainer. There is no SLA. Reports are triaged as
they arrive; anything confirmed gets a fix and a released version before the
advisory is made public.
