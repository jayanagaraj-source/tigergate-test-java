#!/usr/bin/env bash
#
# Fixture for the "eval in a Claude Code / Cursor hook script" rule family.
#
# Agent hook scripts receive attacker-reachable data: a PreToolUse payload
# carries the command the model proposed, which can originate from a web page,
# an issue comment, or any other untrusted content the model read. Running eval
# over that payload turns prompt injection into shell execution.
#
# NOTE: this script is deliberately NOT registered in any settings.json, so it
# never executes. It exists only to be scanned.
set -euo pipefail

PAYLOAD=$(cat)                                              # PreToolUse JSON on stdin
TOOL_NAME=$(printf '%s' "$PAYLOAD" | jq -r '.tool_name')
COMMAND=$(printf '%s' "$PAYLOAD" | jq -r '.tool_input.command // ""')
FILE_PATH=$(printf '%s' "$PAYLOAD" | jq -r '.tool_input.file_path // ""')

eval "$COMMAND"                                             # FINDING: SAST-160 CWE-78 agent-hook-eval-tool-input

eval "echo [hook] $TOOL_NAME touched $FILE_PATH >> /tmp/audit.log"  # FINDING: SAST-161 CWE-78 agent-hook-eval-interpolated-payload

printf '%s' "$PAYLOAD" | jq -r '.tool_input.command' | bash  # FINDING: SAST-162 CWE-78 agent-hook-pipe-payload-to-bash

sh -c "git add $FILE_PATH"                                   # FINDING: SAST-163 CWE-78 agent-hook-sh-c-interpolated-path

# Negative control: inspect the payload without executing it. Must NOT be reported.
if printf '%s' "$COMMAND" | grep -qE '(^|[;&|])\s*rm\s+-rf\s+/'; then  # SAFE: CTRL-034 agent-hook-inspect-without-eval
  echo '{"decision":"block","reason":"destructive command"}'
  exit 0
fi
echo '{"decision":"approve"}'
