#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 VERSION PLATFORM" >&2
  exit 2
fi

version="$1"
platform="$2"
project_dir="$(cd -- "$(dirname -- "$BASH_SOURCE")/.." && pwd)"
binary="${MUTTE_BINARY:-$project_dir/target/release/mutte}"
output_dir="${MUTTE_DIST_DIR:-$project_dir/dist}"
bundle_name="mutte-$version-$platform"
archive_name="$bundle_name.tar.gz"
stage_parent="$(mktemp -d "${TMPDIR:-/tmp}/mutte-package.XXXXXX")"

cleanup() {
  rm -rf -- "$stage_parent"
}
trap cleanup EXIT

if [ ! -x "$binary" ]; then
  echo "Mutte binary does not exist or is not executable: $binary" >&2
  exit 1
fi

mkdir -p "$stage_parent/$bundle_name" "$output_dir"
install -m 0755 "$binary" "$stage_parent/$bundle_name/mutte"
install -m 0644 "$project_dir/README.md" "$stage_parent/$bundle_name/README.md"
install -m 0644 "$project_dir/LICENSE" "$stage_parent/$bundle_name/LICENSE"
{
  echo "version=$version"
  echo "platform=$platform"
  echo "commit=${GITHUB_SHA:-$(git -C "$project_dir" rev-parse HEAD)}"
  echo "protocol=mutte/0.8-alpha"
} > "$stage_parent/$bundle_name/BUILD-INFO"

tar -C "$stage_parent" -czf "$output_dir/$archive_name" "$bundle_name"
(
  cd "$output_dir"
  shasum -a 256 "$archive_name" > "$archive_name.sha256"
)

echo "$output_dir/$archive_name"
