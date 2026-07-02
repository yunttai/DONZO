# Secure Review Checklist

Look for:

- command injection
- path traversal
- unsafe recursive deletes or moves
- missing scope checks before network actions
- unbounded concurrency or rate limits
- secret logging
- unsafe default enablement of OAST, fuzzing, brute force, or exploit modules
- report generation that includes raw secrets or overstates validation
- tests that only cover happy paths
