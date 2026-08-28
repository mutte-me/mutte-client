# Mutte terminal client

Quiet, encrypted, terminal-first chat for Linux and macOS, with optional native
Omarchy integration.

This public repository is a reproducible client-only export from Mutte's private
operations monorepo. `SOURCE-COMMIT` identifies the exact reviewed monorepo
revision for every source commit. The relay image and production deployment
credentials are not published here.

> Mutte is alpha software. Its external protocol, cryptography, backend, and
> client audits are not complete. Do not rely on it for high-risk communication.

## Install from source

The pinned toolchain is Rust 1.98. Linux also needs `pkg-config` and the D-Bus
development headers; macOS needs the Xcode Command Line Tools.

```bash
git clone https://github.com/yuramelesh/mutte-client.git
cd mutte-client
./scripts/install-client.sh
```

The client connects to `https://api.mutte.me` by default. Use
`MUTTE_SERVER=https://another-relay.example` to select a compatible relay.

Prebuilt, checksummed Linux x86_64/ARM64 and macOS Intel/Apple Silicon archives
will be attached to tagged releases after the signing gate is enabled.

## Platform behavior

- Linux stores the encrypted-vault master key through Secret Service and opens
  passkey ceremonies with Omarchy or `xdg-open`.
- macOS stores the master key in Apple Keychain and opens passkey ceremonies
  through Launch Services.
- If secure storage is unavailable on first launch, Mutte creates an
  Argon2id-protected password vault.
- The Trust Lens palette works everywhere. `MUTTE_THEME_FILE` can point to a
  compatible live-reloaded `colors.toml`; Omarchy themes are detected
  automatically.

Run `mutte --help` for configuration and `mutte --demo` for the offline visual
shell.

## Source boundary

The public export contains the Ratatui adapter, headless messaging engine,
OpenMLS boundary, encrypted local store, shared wire types, and frozen client
contracts. It intentionally excludes relay implementation and deployment code.

Mutte is licensed under [AGPL-3.0-only](LICENSE). Security limitations and the
current protocol freeze are documented in
[`contracts/COMPATIBILITY.md`](contracts/COMPATIBILITY.md). Report suspected
vulnerabilities privately according to [`SECURITY.md`](SECURITY.md).
