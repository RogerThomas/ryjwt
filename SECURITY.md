# Security policy

## Reporting a vulnerability

Please report security issues privately, through GitHub:
[report a vulnerability](https://github.com/RogerThomas/ryjwt/security/advisories/new). Don't open
a public issue for one.

Say what you found, which ryjwt version, and how to reproduce it (a token, key and call that show
it, if you can). You'll get a reply there, and the fix is released, with an advisory, before the
issue is made public.

## Supported versions

Fixes go into the latest release only. ryjwt is 0.x, so upgrade to the latest to get them.

## Scope

ryjwt checks signatures with [aws-lc](https://github.com/aws/aws-lc), through aws-lc-rs. Report a
flaw in aws-lc itself to AWS, as its
[security policy](https://github.com/aws/aws-lc/blob/main/SECURITY.md) says. Anything in ryjwt's own
code (parsing tokens, checking claims, loading keys and JWKS, the JWKS client) belongs here.

[Security notes](https://rogerthomas.github.io/ryjwt/security/) covers what ryjwt protects you from,
and what's up to you.
