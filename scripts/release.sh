#!/usr/bin/env bash
#
# Deliberately insecure shell fixtures for shell-injection SAST rules
# (the SH-0xx / CWE-78 rule family). Every sink below takes genuinely
# untrusted input: a script argument, an environment variable, or the body
# of an HTTP response. These are TRUE POSITIVES and must be reported.
#
# Contrast with ./gradlew in this repo, which contains a structurally similar
# `eval` that is NOT attacker-controlled and is marked as a negative control.
#
# Do not run.
set -euo pipefail

VERSION="${1:-}"          # untrusted: first positional argument
TARGET="${DEPLOY_TARGET:-}" # untrusted: environment variable
REGISTRY="${2:-}"

# ---------------------------------------------------------------------------
# eval with user input -- the exact shape of the SH-002 rule
# ---------------------------------------------------------------------------

eval "$VERSION"                                   # FINDING: SAST-140 CWE-78 shell-eval-direct-user-input

eval "echo Deploying $VERSION to $TARGET"         # FINDING: SAST-141 CWE-78 shell-eval-interpolated-user-input

eval "export BUILD_$VERSION=1"                    # FINDING: SAST-142 CWE-78 shell-eval-assignment-from-argument

eval "$(cat /tmp/deploy.conf)"                    # FINDING: SAST-143 CWE-78 shell-eval-command-substitution-file

eval "$(curl -fsSL "https://config.example.com/$TARGET")"  # FINDING: SAST-144 CWE-78 shell-eval-remote-response

# ---------------------------------------------------------------------------
# Piping untrusted input directly to eval / bash / sh
# ---------------------------------------------------------------------------

curl -fsSL "https://get.example.com/install.sh" | bash      # FINDING: SAST-145 CWE-494 shell-curl-pipe-bash

wget -qO- "https://get.example.com/setup.sh" | sh           # FINDING: SAST-146 CWE-494 shell-wget-pipe-sh

echo "$VERSION" | bash                                      # FINDING: SAST-147 CWE-78 shell-pipe-user-input-to-bash

cat /tmp/untrusted-commands.txt | sh                        # FINDING: SAST-148 CWE-78 shell-pipe-file-to-sh

curl -fsSL "https://config.example.com/$TARGET" | eval "$(cat)"  # FINDING: SAST-149 CWE-78 shell-pipe-remote-to-eval

# ---------------------------------------------------------------------------
# Other command-execution sinks with untrusted data
# ---------------------------------------------------------------------------

sh -c "docker push $REGISTRY/app:$VERSION"        # FINDING: SAST-150 CWE-78 shell-sh-c-interpolated-input

bash -c "git tag -a $VERSION -m release"          # FINDING: SAST-151 CWE-78 shell-bash-c-interpolated-input

RESULT=`git log --oneline $VERSION`               # FINDING: SAST-152 CWE-78 shell-backtick-substitution-user-input
echo "$RESULT"

source "/etc/deploy/$TARGET.env"                  # FINDING: SAST-153 CWE-829 shell-source-user-controlled-path

. "$HOME/.config/$VERSION/profile"                # FINDING: SAST-154 CWE-829 shell-dot-include-user-controlled-path

rm -rf /var/cache/$VERSION/*                      # FINDING: SAST-155 CWE-78 shell-unquoted-expansion-in-destructive-command

# ---------------------------------------------------------------------------
# Negative controls: correct handling. Must NOT be reported.
# ---------------------------------------------------------------------------

case "$TARGET" in                                 # SAFE: CTRL-031 shell-allowlisted-input
  staging|production) ;;
  *) echo "unknown target" >&2; exit 1 ;;
esac

printf 'Deploying %s to %s\n' "$VERSION" "$TARGET"   # SAFE: CTRL-032 shell-printf-no-interpretation

docker push "$REGISTRY/app:$VERSION"                 # SAFE: CTRL-033 shell-quoted-argv-no-shell
