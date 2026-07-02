# Scope Policy

Allowed targets must match at least one explicit in-scope domain, URL, or IP
range and must not match any out-of-scope domain, URL, path, or test type.

Wildcard domains such as `*.example.com` include subdomains but do not imply
unrelated sibling domains. A concrete out-of-scope entry wins over a wildcard
in-scope entry.

Network-facing tools require:

- scope file
- authorized-only mode
- rate limit
- output path
- redaction before report generation

Blocked activities include DoS, brute force, credential stuffing, phishing,
social engineering, malware upload, destructive testing, data modification,
automatic exploitation, automatic submission, and secret validation.
