# Security

This library parses untrusted metadata, often received over the air, so we treat crashes, hangs, unbounded memory growth or recursion and memory safety problems in the C API as security issues.

## Reporting a vulnerability

Please do not open a public issue. Report it privately through GitHub: go to the repository's **Security** tab and choose **Report a vulnerability**.

Include what you can of the following: the version or commit, a description of the problem, and an input that reproduces it (a hex dump of the KLV bytes is fine). We will acknowledge the report within a few working days and keep you informed while we work on a fix. Once a fix is released we are happy to credit you, unless you prefer otherwise.

## Supported versions

Until 1.0, only the latest release receives security fixes.
