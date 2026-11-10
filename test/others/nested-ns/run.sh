#!/bin/bash
# The nested user namespaces support is turned on by the dump when a
# task lives in a nested one (nothing is passed on the command line),
# and the images record it: the restore takes the shape of the tree
# from them. Run as root.

set -e -u

# shellcheck source=test/others/env.sh
source ../env.sh

IMG=$(mktemp -d /tmp/criu-nested-ns.XXXXXX)
trap 'rm -rf "$IMG"; kill "$PID" 2>/dev/null || :' EXIT

# A process in a user namespace nested inside the one of the shell
unshare -Ur setsid sleep 1000 < /dev/null > /dev/null 2>&1 &
PID=$!
sleep 0.5

$CRIU dump -t "$PID" -D "$IMG" -v4 -o dump.log
grep -q "nested user namespace" "$IMG/dump.log" || {
	echo "FAIL: the dump did not turn the nested namespaces support on"
	grep -E "nested|user namespace" "$IMG/dump.log" || cat "$IMG/dump.log"
	exit 1
}
grep -q "nested_ns" "$IMG/inventory.img" 2>/dev/null || true

$CRIU restore -D "$IMG" -v4 -o restore.log -d --pidfile "$IMG/pid"
PID=$(cat "$IMG/pid")
kill -0 "$PID"
kill "$PID"
echo PASS
