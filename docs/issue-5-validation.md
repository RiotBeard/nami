# Issue #5 validation

Validated on 2026-09-15 against base commit
`35fd1702da88b3a97efdbe119a401596a999f044`.

## Automated

- `npm ci` completed using the lockfile, without dependency changes.
- `npm test`: **1,250 passed, 0 failed**. Localhost access was required by the
  existing browser-sharing tests; the restricted sandbox rejected their binds.
- New regression tests use dummy credentials and injected process boundaries.
  They exercise the real PTY creation handler, renderer IPC and snapshot/restore,
  MCP, ACP, status/PATH probes, Codex usage, custom executable binding, settings
  overrides, redacted diagnostics, and environment immutability.
- Existing transcription tests passed unchanged.
- JavaScript syntax checks and `git diff --check` passed.

The first run before dependency installation reported missing modules. After
installation and allowing localhost, there were no remaining suite failures.

## Development-app smoke check

Ran the checkout with `npm start` and the separate **Nami-dev** profile. The
installed `/Applications/Nami.app` was not changed. Checks used an empty temporary
folder and sent no model prompts.

- Codex launched to its prompt; Nami recognized the existing ChatGPT sign-in.
- Claude launched to its prompt, but displayed **Not logged in** and its status
  check returned unknown. Claude subscription authentication is therefore **not
  verified** on this machine; no login/logout was performed.
- Quit and relaunched Nami-dev: both unused agent tiles restored, retaining their
  explicit agent metadata. Resuming a conversation with actual messages was not
  manually tested; the automated new/resumed launch checks passed.
- A plain terminal and an installer carrying an agent ID both received **none**
  of a temporary saved dummy credential.
- A custom profile appeared in the launcher and received its one granted dummy
  credential, while an unrelated saved dummy credential was absent.
- The updated Keys explanation rendered in the app.

Codex displayed an MCP startup warning: its Context7 server is not logged in.
No connector login was attempted. The host shell also reported protected-path
errors for existing Google SDK startup snippets. Live provider calls and connector
handshakes were not tested with real credentials.

All smoke-test agent tiles were closed and the original Nami-dev settings were
restored after testing. See [credential permissions](child-process-credentials.md)
for defaults, opt-in configuration, and the limits of initial-environment filtering.

## Final security review

Reviewed credential disclosure, IPC authorization, shell/HTML inputs, JSON
parsing, and TLS-related changes. Fixed three validated gaps with regression tests:
custom harnesses cannot claim built-in agent grants; library-agent filenames
are shell-quoted when passed as launch arguments; and run-session commands must
match the selected agent's main-process registry commands (or its supported,
exactly quoted library-agent arguments) before receiving grants. No SQL execution or TLS
verification changes were introduced. New custom IDs are validated and rendered
through existing HTML escaping; process/environment contents are not logged.

The main process validates built-in run commands and custom executable bindings.
This environment policy is not an application sandbox against a compromised
renderer or same-user processes. Shell startup files, credential files, and unregistered environment
secrets retain the documented limitations.

## Additional native computer-use verification

Used the native Electron window through computer use, running `npm start` with
Nami-dev and disposable dummy keys/profiles:

- Confirmed the corrected Keys subtitle and explanation.
- A custom profile received its granted saved key and inherited-only key; the
  saved value beat the inherited value. An unrelated saved key stayed absent.
- An empty-grant custom profile received no saved dummy key.
- An ordinary terminal received neither saved nor inherited dummy keys.
- PATH and HOME remained present in all fixture reports.
- A clean restart restored the custom profile with the same grants and restored
  the ordinary terminal. Overlapping test instances initially interfered with
  the restart check; they were stopped before the successful clean run.
- Codex again reached its prompt and the launcher recognized ChatGPT sign-in.
- Closed all test tiles, stopped test processes, and restored the original
  Nami-dev settings byte-for-byte. The installed application was untouched.

MCP/ACP spawn policy, malformed settings, legacy restoration and installer
precedence have automated boundary tests; this pass did not manually exercise
real ACP/provider sessions or every external connector. Claude authentication
remains unverified as described above.

`npm run check:security`, rerun with network access, reports zero known
vulnerabilities for both all dependencies and runtime dependencies. Its Electron
freshness gate fails: the unchanged lockfile pins 43.7.0 while 43.7.1 is available
on that major. This is a separate dependency-maintenance finding, not an audit
advisory introduced by this change; no dependency versions were changed.
