#!/bin/bash

# Script to automate creating a (draft) release.
#
# After running this script, manually add release notes and publish the
# release. CI will then make release builds and attach them automatically.

set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

# Show usage on invalid args.
if [ $# -ne 1 ]; then
  echo "Usage: $0 <version>"
  exit 64
fi

# Check if git tree is clean.
if [ ! -z "$(git status --porcelain)" ]; then
  echo "Working directory is not clean."
  exit 1
fi

# Summarize actions.
echo "About to create a release $1, with recent commits:"
echo
git log --oneline --max-count 10 | cat
echo
read -p "Continue? (y/n)" CONT
if [ "$CONT" != "y" ]; then
  echo "Cancelled."
  exit 1
fi

# Echo commands from here.
set -x

# Update the version in Cargo.toml.
#
# Assumes it's somewhere in the first 5 lines, because we want to avoid
# replacing dependency versions.
sed -i '' -e "1,5 s/^version = \".*\"/version = \"$1\"/" Cargo.toml

# Run Cargo to have it update Cargo.lock.
cargo check

# Create a commit and push.
git commit -m "Version $1" Cargo.toml Cargo.lock
git push

# Create a draft release on GitHub.
gh release create "v$1" --draft --title "v$1"
