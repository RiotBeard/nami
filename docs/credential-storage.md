# Saved API-key protection

Nami keeps ordinary preferences in `settings.json` and saved API keys in
`credentials.json` in the same app profile. The latter contains a versioned
Electron safeStorage ciphertext; its decrypted payload, including the migration
journal, exists only in the main process. Writes use an exclusive 0600 temporary
file and atomic rename. Newly encrypted data is checked before replacing the
previous vault, then reread and validated before plaintext cleanup. No plaintext
backup is created.

On macOS, safeStorage uses the app's Keychain protection. Windows uses DPAPI.
Linux requires an identified system secret store: `basic_text` and `unknown`
backends are rejected, as are unsupported platforms. Nami never enables plaintext encryption or saves new keys unencrypted.
This is protection at rest, not a process sandbox. Authorized consumers receive
plaintext in memory; agent processes still have the user's normal privileges.
The synchronous safeStorage API follows the existing browser-vault pattern and
may trigger an OS unlock/access prompt. App identity/signature changes can affect
Keychain access.

## Migration

After Electron is ready, before restoring windows and sessions, Nami imports
`envKeys`, `openaiKey`, `elevenKey`, and `sttKey` from the current profile only.
Named keys and legacy provider keys remain separate. Speech lookup still prefers
a named saved key, then its legacy provider key, then the shell environment.
Environment-only keys are never imported or saved automatically.

The first encrypted commit records imported identifiers, deletion tombstones,
and a pending migration state. Nami rereads and decrypts that commit and verifies
its contents before removing plaintext fields. Cleanup rereads settings so other
preferences survive. A second encrypted commit marks completion. Each transaction
is synchronous in the main process; handlers in multiple windows cannot interleave.
If an external writer changes source keys during migration, cleanup stops and
preserves that source for retry. Completed startup validates the vault without
rewriting it. Run separate development processes with separate profiles, as
described in CONTRIBUTING.md; the store does not coordinate independent processes.

A pending migration can be retried after interruption. Existing encrypted values,
previously imported identifiers, and deletion tombstones win over old plaintext.
Once migration is complete, restored plaintext fields are treated as stale and
removed, not reimported. Re-enter intentionally restored keys through Settings.
Deleting `OPENAI_API_KEY` or `ELEVENLABS_API_KEY` also removes the associated legacy
provider key. Legacy entries, including unused `sttKey`, are separately visible
in Keys with explicit Show and Remove controls.

Migration does not erase historical backups or guarantee physical erasure of old
filesystem blocks. Connector/MCP configuration files and the browser password
vault have separate storage lifecycles and are outside this change.

## Recovery

When encryption is unavailable, decryption fails, a format version is unknown, or
migration cannot finish, Nami preserves the source files and blocks saved-key
operations. Settings → Keys shows an error and **Retry secure storage**, including
when a save fails while the pane is already open.

Only saved keys are affected. Sessions still start, without the saved keys, and
print one dim notice pointing at Settings → Keys. Agent status, the local speech
engine, ordinary preferences, and keys exported in the shell Nami was started
from all keep working; a keyed speech provider with no key anywhere reports that
saved keys are unavailable instead of "no API key". Reads are served from the
vault this process last verified, so one failed save (a full disk, a locked key
store) returns an error for that save and leaves existing keys usable. The store
becomes unavailable only when the vault on disk no longer verifies.

An unreadable `settings.json` is reported separately, naming the file, with a
**show settings.json** link in Settings → Keys. Nami never replaces it through a
preference save. It blocks a migration that has not finished, because the keys
to import live there, but not a vault that has already been migrated.

Unlock the system key store, resolve permissions or disk-space problems, then
retry. For damaged ciphertext, quit Nami and restore a known-good encrypted copy
belonging to the same app profile and OS identity. Never substitute an empty
vault for an unreadable one. Without a recoverable encrypted copy/system key,
keys must be re-entered; do not delete source files until that loss is understood.
Nami does not silently reset a vault, overwrite unknown formats, or print raw
crypto exceptions. Normal IPC responses contain no decrypted key collection;
only an explicit Show action returns one value.

Development (`npm start`) uses `Nami-dev`; the installed app uses its own profile.
Do not copy the installed app's settings into a development profile for testing.

## Validation

`npm test` runs offline with injected encryption and disposable files; it never
uses the real Keychain. Coverage includes migration interruption, source retention,
mixed states, deletions, key precedence, corrupt records, write/encryption errors,
IPC responses, atomic writes and permissions.

`node scripts/smoke-credentials.cjs` separately launches `npm start` four times
with a disposable `Nami-dev` profile and dummy secrets. It uses real safeStorage,
checks migration, Reveal, masking, encrypted persistence and deletion across
restarts, tests the Settings controls and recovery after damaged ciphertext,
and then removes the profile. The script opens a localhost debugging
endpoint only for these test launches and closes the app processes afterward.
It may require an OS Keychain prompt. No packaging or installed-app replacement
is involved. This verifies development-app behavior, not signed-release identity
or Keychain behavior across app updates.
