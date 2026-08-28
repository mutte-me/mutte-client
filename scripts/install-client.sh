#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "$BASH_SOURCE")/.." && pwd)"
install_prefix="${MUTTE_INSTALL_PREFIX:-$HOME/.local}"
bin_dir="$install_prefix/bin"

case "$(uname -s)" in
  Linux | Darwin) ;;
  *)
    echo "Mutte's terminal client currently supports Linux and macOS." >&2
    exit 1
    ;;
esac

cd "$project_dir"
cargo build --locked --release --package mutte
mkdir -p "$bin_dir"
install -m 0755 "$project_dir/target/release/mutte" "$bin_dir/mutte"

echo "Mutte installed at $bin_dir/mutte"
case ":${PATH:-}:" in
  *":$bin_dir:"*) ;;
  *) echo "Add $bin_dir to PATH, then run: mutte" ;;
esac
