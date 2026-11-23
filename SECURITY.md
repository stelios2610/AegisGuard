# Reporting a vulnerability

FGUARD is a network gateway. A vulnerability report should go to the maintainer in private, not in a public issue.

Include the version from `version.json`, what you observed, and the smallest steps that show the problem. Give the maintainer time to ship a signed update before publishing details.

Updates are installed only when `version.json` is signed with the release private key and the archive sha256 matches. Do not send exploit payloads to a customer appliance as a test.
