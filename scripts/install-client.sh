#!/bin/sh
set -eu

repository="yuramelesh/mutte-client"
version="${MUTTE_VERSION:-}"
staged_binary=""
temporary_dir=""

say() {
  printf '%s\n' "$*"
}

fail() {
  printf 'mutte installer: %s\n' "$*" >&2
  exit 1
}

need_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

cleanup() {
  if [ -n "$staged_binary" ]; then
    rm -f "$staged_binary"
  fi
  if [ -n "$temporary_dir" ]; then
    rm -rf "$temporary_dir"
  fi
}
trap cleanup EXIT HUP INT TERM

for command_name in curl grep id install mkdir mktemp mv sed tar uname; do
  need_command "$command_name"
done

case "$(uname -s)" in
  Linux) operating_system="linux" ;;
  Darwin) operating_system="macos" ;;
  *) fail "only Linux and macOS are currently supported" ;;
esac

case "$(uname -m)" in
  x86_64 | amd64) architecture="x86_64" ;;
  arm64 | aarch64) architecture="aarch64" ;;
  *) fail "unsupported CPU architecture: $(uname -m)" ;;
esac

platform="$operating_system-$architecture"

if [ -z "$version" ]; then
  releases_url="https://api.github.com/repos/$repository/releases?per_page=1"
  release_json="$(curl \
    --fail \
    --silent \
    --show-error \
    --location \
    --proto '=https' \
    --tlsv1.2 \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    "$releases_url")" || fail \
      "could not resolve the newest release; set MUTTE_VERSION explicitly"
  version="$(printf '%s\n' "$release_json" | sed -n \
    's/^[[:space:]]*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | \
    sed -n '1p')"
fi

printf '%s\n' "$version" | grep -Eq \
  '^v[0-9A-Za-z][0-9A-Za-z.+-]*$' || fail "invalid release version: $version"

if [ -n "${MUTTE_INSTALL_DIR:-}" ]; then
  install_dir="$MUTTE_INSTALL_DIR"
elif [ -n "${MUTTE_INSTALL_PREFIX:-}" ]; then
  install_dir="$MUTTE_INSTALL_PREFIX/bin"
elif [ "$(id -u)" -eq 0 ]; then
  install_dir="/usr/local/bin"
else
  install_dir="${HOME:?HOME must be set}/.local/bin"
fi

version_number="${version#v}"
archive="mutte-$version_number-$platform.tar.gz"
release_base="https://github.com/$repository/releases/download/$version"
temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/mutte-install.XXXXXX")"

say "Installing Mutte $version for $platform..."
curl \
  --fail \
  --silent \
  --show-error \
  --location \
  --proto '=https' \
  --tlsv1.2 \
  "$release_base/$archive" \
  --output "$temporary_dir/$archive"
curl \
  --fail \
  --silent \
  --show-error \
  --location \
  --proto '=https' \
  --tlsv1.2 \
  "$release_base/$archive.sha256" \
  --output "$temporary_dir/$archive.sha256"

if command -v sha256sum >/dev/null 2>&1; then
  (
    cd "$temporary_dir"
    sha256sum --check "$archive.sha256"
  )
elif command -v shasum >/dev/null 2>&1; then
  (
    cd "$temporary_dir"
    shasum -a 256 -c "$archive.sha256"
  )
else
  fail "sha256sum or shasum is required to verify the download"
fi

tar -xzf "$temporary_dir/$archive" -C "$temporary_dir"
binary="$temporary_dir/mutte-$version_number-$platform/mutte"
[ -f "$binary" ] || fail "release archive did not contain the Mutte binary"
[ -x "$binary" ] || fail "release archive contained a non-executable binary"

mkdir -p "$install_dir"
staged_binary="$install_dir/.mutte-install.$$"
install -m 0755 "$binary" "$staged_binary"
mv -f "$staged_binary" "$install_dir/mutte"
staged_binary=""

"$install_dir/mutte" --version >/dev/null
say "Mutte installed at $install_dir/mutte"

case ":${PATH:-}:" in
  *":$install_dir:"*) say "Run: mutte" ;;
  *) say "Add $install_dir to PATH, then run: mutte" ;;
esac
