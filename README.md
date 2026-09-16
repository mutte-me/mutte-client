<p align="center">
  <img src="assets/mutte-wordmark.svg" alt="Mutte" width="780">
</p>

# Mutte terminal client

Quiet, encrypted, terminal-first chat for Linux and macOS, with optional native
Omarchy integration.

This public repository is a reproducible client-only export from Mutte's private
operations monorepo. `SOURCE-COMMIT` identifies the exact reviewed monorepo
revision for every source commit. The relay image and production deployment
credentials are not published here.

> Mutte is alpha software. Its external protocol, cryptography, backend, and
> client audits are not complete. Do not rely on it for high-risk communication.

## Install

```bash
curl -sfL https://get.mutte.me | sh -
```

The installer detects Linux or macOS and the native CPU architecture, downloads
the newest published archive, verifies its SHA-256 checksum, and installs
`mutte` into `~/.local/bin`. It does not require Rust or `cargo`. Re-run the same
command to upgrade. Set `MUTTE_VERSION=v0.1.0-alpha.7` to pin a release or
`MUTTE_INSTALL_DIR=/another/bin` to choose the destination.

With Homebrew:

```bash
brew install mutte-me/tap/mutte
```

To inspect the installer before running it:

```bash
curl -sfL https://get.mutte.me -o install-mutte.sh
less install-mutte.sh
sh install-mutte.sh
```

## Build from source

The pinned toolchain is Rust 1.98. Linux also needs `pkg-config` and the D-Bus
development headers; macOS needs the Xcode Command Line Tools.

```bash
git clone https://github.com/mutte-me/mutte-client.git
cd mutte-client
cargo build --locked --release --package mutte
```

The client connects to `https://api.mutte.me` by default. Use
`MUTTE_SERVER=https://another-relay.example` to select a compatible relay.

For browserless email signup or sign-in, run:

```bash
mutte --auth email
```

The client prompts for profile and email details, sends a device-bound one-time
link, and accepts the full link or its raw token at a hidden prompt. A new email
creates an account; a bound email signs in only with its exact handle. Accounts
that have only a passkey and no bound email must use the default browser flow.
Press Enter at the hidden link prompt to correct the details and resend while
keeping the same pending device authorization. This links a new terminal
device; re-adding a revoked device identity is not supported in the alpha
contract.

Prebuilt, checksummed Linux x86_64/ARM64 and macOS Intel/Apple Silicon archives
are attached to tagged releases. macOS binaries are signed with Developer ID,
submitted to Apple, and the release remains blocked until both architectures are
accepted by the notarization service.

## Platform behavior

- Linux stores the encrypted-vault master key through Secret Service and opens
  passkey ceremonies with Omarchy or `xdg-open`.
- macOS stores the master key in Apple Keychain and opens passkey ceremonies
  through Launch Services.
- If secure storage is unavailable on first launch, Mutte creates an
  Argon2id-protected password vault.
- Message history and pending outbox state are isolated by canonical relay
  origin, account, and device. A released global vault is preserved and copied
  once only when its encrypted session matches all three bindings.
- The default Mutte violet palette works everywhere. `MUTTE_THEME_FILE` can point to a
  compatible live-reloaded `colors.toml`; Omarchy themes are detected
  automatically.

Run `mutte --help` for configuration and `mutte --demo` for the offline visual
shell.

## Reading and replying

`Tab` / `Shift+Tab` cycles Chats, Messages, message input, and command input.
Use `F1`–`F4` to focus them directly. In Messages, Up / Down selects an individual
message, `R` replies, `T` opens a thread, `O` opens a quoted original, and Enter
starts writing. `E` opens the reaction picker; choose with arrows, Tab, or 1–6,
then Enter toggles it. `End` selects the newest message; `Esc` returns from a thread.
Main chats and threads keep separate drafts during the session.

Messages use individual, content-sized, square-cornered blocks in a centered 72-column reading
lane. Your bubbles sit on the right, but all text remains left-aligned. Each
bubble contains its own timestamp and receipt: `✓` delivered, `✓✓` read, or an
explicit queued/sent/cancelled label. Consecutive messages stack tightly without
merging; sender/time/day/unread/thread boundaries add a group break. `NO_COLOR`
uses outlines and explicit ownership/status labels. Selection stays per message.

## Attachments

Press `Ctrl+O` in a chat (or `Ctrl+K`, then `A`) to open the local file-browser
modal. Arrows and Enter browse folders; typing filters filenames. `Ctrl+L`
accepts a literal path, `F5` shows hidden files, `Ctrl+G` opens Home, and `Ctrl+D`
opens Downloads. After choosing a file, review its name, size, path, and
destination; Enter confirms Send, Tab chooses another action, and Esc goes back.
`P` previews bounded UTF-8 text/code or a true-color terminal-cell image; unsafe or
unsupported binaries remain metadata-only. Up/Down scroll long details. The
message draft is kept and sends separately.

Files up to 32 MiB are encrypted locally and sent to the selected chat or thread.
Queued uploads preserve that destination after restart; keep the source file
available until they finish. Ctrl+C quits an active transfer; journaled work
resumes at next launch. In Messages (`F2`), select a file and press `A` for
details, then Enter / `D` to download. Verified files show their local path;
nothing is opened automatically. `/send PATH` and `/download ID` still work.

## Source boundary

The public export contains the Ratatui adapter, headless messaging engine,
OpenMLS boundary, encrypted local store, shared wire types, and frozen client
contracts. It intentionally excludes relay implementation and deployment code.

Mutte is licensed under [AGPL-3.0-only](LICENSE). Security limitations and the
current protocol freeze are documented in
[`contracts/COMPATIBILITY.md`](contracts/COMPATIBILITY.md). Report suspected
vulnerabilities privately according to [`SECURITY.md`](SECURITY.md).
