#!/usr/bin/env bash
# Runs Gradle with the given arguments, and runs it again when it failed only because a
# repository could not be reached. The first release of FirstAlert, whose workflows TypeFace
# Droplet and Replay Integrity share, failed this way: on a runner with an empty Gradle home, a
# plugin that the other jobs of the same run had just downloaded "could not be resolved". A
# build or test failure is not retried: it fails at once, as it should. Gradle's own message does not tell a missing artifact from an unreachable repository,
# so a dependency that is really missing fails after the last attempt, a few minutes later.
set -uo pipefail

attempts=3
log="$(mktemp)"
for attempt in $(seq 1 "$attempts"); do
  if ./gradlew "$@" 2>&1 | tee "$log"; then
    exit 0
  fi
  if ! grep -qE "could not resolve plugin artifact|Could not resolve [^ ]+:[^ ]+|Could not (GET|HEAD) '|Received status code (408|429|5[0-9][0-9])|Connection reset|Read timed out|Connect timed out|Remote host terminated the handshake" "$log"; then
    exit 1
  fi
  if [ "$attempt" -lt "$attempts" ]; then
    wait=$((attempt * 60))
    echo "::warning::Gradle could not reach a dependency repository (attempt $attempt of $attempts); trying again in $wait s"
    sleep "$wait"
  fi
done
echo "::error::Gradle could not reach a dependency repository in $attempts attempts"
exit 1
