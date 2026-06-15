---
default: patch
---

# Cap exponential scan backoff

Cap the exponential backoff for failed host scans at 3 days. Previously the backoff was unbounded, which meant a host with a high failure streak could overflow `time.Duration` and be permanently excluded from scanning.
