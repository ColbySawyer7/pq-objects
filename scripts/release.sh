#!/usr/bin/env bash
# Bump version, tag, and push so GitHub Actions publishes to crates.io.
#
# Usage:
#   ./scripts/release.sh           # interactive (asks major? then minor?)
#   ./scripts/release.sh patch     # 0.1.0 -> 0.1.1
#   ./scripts/release.sh minor     # 0.1.0 -> 0.2.0
#   ./scripts/release.sh major     # 0.1.0 -> 1.0.0
#
# Requires: git, gh (optional), clean main branch, CARGO_REGISTRY_TOKEN secret on the repo.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

die() {
  echo "error: $*" >&2
  exit 1
}

current_version() {
  cargo metadata --no-deps --format-version 1 |
    jq -r '.packages[] | select(.name == "pq-objectstore") | .version'
}

bump_version() {
  local kind="$1"
  local major minor patch
  IFS=. read -r major minor patch <<<"$2"
  case "$kind" in
    major) echo "$((major + 1)).0.0" ;;
    minor) echo "${major}.$((minor + 1)).0" ;;
    patch) echo "${major}.${minor}.$((patch + 1))" ;;
    *) die "unknown bump kind: $kind (use major|minor|patch)" ;;
  esac
}

choose_kind() {
  if [[ $# -ge 1 ]]; then
    echo "$1"
    return
  fi

  local ans
  read -r -p "Is this a major release? [y/N] " ans
  if [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]]; then
    echo "major"
    return
  fi

  read -r -p "Minor release (else patch)? [y/N] " ans
  if [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]]; then
    echo "minor"
    return
  fi

  echo "patch"
}

set_cargo_version() {
  local new="$1"
  # Only rewrite the package version line near the top of Cargo.toml.
  sed -i "0,/^version = \".*\"/{s/^version = \".*\"/version = \"${new}\"/}" Cargo.toml
}

update_changelog() {
  local new="$1"
  local today
  today="$(date -u +%Y-%m-%d)"
  local tmp
  tmp="$(mktemp)"

  if grep -q "^## \[Unreleased\]$" CHANGELOG.md; then
    awk -v ver="$new" -v day="$today" '
      BEGIN { done = 0 }
      /^## \[Unreleased\]$/ && !done {
        print
        print ""
        print "## [" ver "] - " day
        done = 1
        next
      }
      { print }
    ' CHANGELOG.md >"$tmp"
    mv "$tmp" CHANGELOG.md
  else
    die "CHANGELOG.md missing ## [Unreleased] section"
  fi
}

main() {
  local kind old new tag

  [[ -z "$(git status --porcelain)" ]] || die "working tree is dirty; commit or stash first"
  [[ "$(git branch --show-current)" == "main" ]] || die "switch to main before releasing"

  git fetch origin main --tags >/dev/null 2>&1 || true
  git merge-base --is-ancestor HEAD origin/main 2>/dev/null ||
    die "local main is not up to date with origin/main (pull first)"

  kind="$(choose_kind "${1:-}")"
  old="$(current_version)"
  new="$(bump_version "$kind" "$old")"
  tag="v${new}"

  if git rev-parse "$tag" >/dev/null 2>&1; then
    die "tag $tag already exists"
  fi

  echo "Bump: ${old} -> ${new} (${kind})"
  read -r -p "Create release ${tag} and push to GitHub Actions? [y/N] " ans
  [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]] || die "aborted"

  set_cargo_version "$new"
  update_changelog "$new"

  [[ "$(current_version)" == "$new" ]] || die "Cargo.toml version did not update to $new"

  git add Cargo.toml CHANGELOG.md
  git commit -m "Release ${tag}"
  git tag -a "$tag" -m "Release ${tag}"
  git push origin main
  git push origin "$tag"

  echo
  echo "Pushed ${tag}. GitHub Actions will:"
  echo "  1. verify tag == Cargo.toml"
  echo "  2. test + package"
  echo "  3. cargo publish (needs CARGO_REGISTRY_TOKEN secret)"
  echo "  4. create GitHub Release"
  echo
  if command -v gh >/dev/null 2>&1; then
    echo "Watch: gh run watch --repo ColbySawyer7/pq-objects"
    gh run list --workflow=release.yml --limit 3 2>/dev/null || true
  fi
}

main "$@"
