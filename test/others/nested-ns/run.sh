#!/bin/bash
# The images dumped with --nested-ns record the option in the inventory:
# a restore without it is refused (the tmpfs archives and the pids of the
# nested namespaces need the option), a restore with it works. Run as root.

set -e -u

# shellcheck source=test/others/env.sh
source ../env.sh

IMG=$(mktemp -d /tmp/criu-nested-ns.XXXXXX)
trap 'rm -rf "$IMG"; kill "$PID" 2>/dev/null || :' EXIT

setsid sleep 1000 < /dev/null > /dev/null 2>&1 &
PID=$!
sleep 0.5

$CRIU dump --nested-ns -t "$PID" -D "$IMG" -v4 -o dump.log
if $CRIU restore -D "$IMG" -v4 -o restore-noflag.log -d --pidfile "$IMG/pid"; then
	echo "FAIL: the restore without --nested-ns of an image dumped with it succeeded"
	kill "$(cat "$IMG/pid")" 2>/dev/null || :
	exit 1
fi
grep -q "dumped with --nested-ns" "$IMG/restore-noflag.log" || {
	echo "FAIL: the restore without --nested-ns failed for another reason"
	cat "$IMG/restore-noflag.log"
	exit 1
}

$CRIU restore --nested-ns -D "$IMG" -v4 -o restore.log -d --pidfile "$IMG/pid"
PID=$(cat "$IMG/pid")
kill -0 "$PID"
kill "$PID"
echo PASS
