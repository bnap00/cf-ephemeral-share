# Security policy

This project is a file-sharing service whose main feature is that the server
cannot read what it stores. Reports that weaken that property are the ones we
most want to hear about.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
[Report a vulnerability](https://github.com/bnap00/cf-ephemeral-share/security/advisories/new).

Do not open a public issue, pull request, or discussion for a suspected
vulnerability. Include the affected commit, the steps to reproduce, and the
impact you expect. I aim to acknowledge reports within a week. This is a
one-person project, so fixes are best effort, but confirmed issues get a GitHub
security advisory and credit unless you ask otherwise.

## Supported versions

Only the latest commit on `main` is supported. There are no release branches.
If you deploy your own copy, pull fixes from `main` and redeploy.

## Scope

In scope:

- Anything that lets the server, Cloudflare, or a network observer recover
  plaintext, filenames, media types, link keys, or passwords
- Weaknesses in the browser or CLI cryptography (`public/crypto.js`,
  `tools/ef.mjs`)
- Bypassing the upload token, expiry, download limits, or revocation
- Script injection or content-type confusion on the deployment's origin
- Leaks of the URL fragment through logs, referrers, caches, or the service
  worker

Out of scope:

- A compromised deployment serving modified JavaScript. The README documents
  this limit; use the CLI client if it matters to you.
- The race on concurrent downloads of a one-read link, which the README
  documents under "Known limits"
- Missing rate limits on deployments that have not enabled the optional
  `[[ratelimits]]` bindings
- Denial of service against your own Cloudflare account quotas
- Reports from automated scanners without a demonstrated impact

## Safe harbor

Good-faith research against your own deployment is welcome. Do not test against
deployments you do not own, and do not access or keep other people's data.
