Vulnerable dependencies scanner (GitLab)

Overview
This tool scans GitLab projects you have access to and reports vulnerable npm packages found in lock and manifest files.

Scanned files
- yarn.lock
- package-lock.json
- npm-shrinkwrap.json
- pnpm-lock.yaml
- package.json (dependencies, devDependencies, optionalDependencies, peerDependencies, resolutions, overrides)

Requirements
- Go 1.21+
- GitLab personal access token with API scope

Environment
- GITLAB_URL: Base URL of GitLab instance, e.g. https://gitlab.example.com
- GITLAB_TOKEN: Personal access token

Usage
Build:
  go build -o vuln-scan

Run:
  GITLAB_URL=<url> GITLAB_TOKEN=<token> ./vuln-scan -v -concurrency 8 -branch-concurrency 4 -file-concurrency 6 -active-within-days 90

Flags
- -v: Verbose logging (project/branch, file progress, summaries)
- -concurrency: Number of projects scanned in parallel (default 6)
- -branch-concurrency: Number of branches scanned in parallel per project (default 3)
- -file-concurrency: Number of files per project scanned in parallel (default 4)
- -include-archived: Include archived projects (default false)
- -active-within-days: Only scan projects with activity within N days (default 90)

Output
JSON printed to stdout with a list of findings per project and file.

Notes
- The scanner scans all branches of recently active projects (by default last 90 days).
- HTTP client is tuned for high parallelism; adjust flags to fit your GitLab limits.

