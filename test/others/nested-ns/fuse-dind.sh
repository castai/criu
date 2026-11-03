#!/bin/bash
# The nested-ns fuse-dind scenario: a tier0 process (the initial user
# namespace) with a fuse server child serving a mount inside a tier1
# nested user+mount namespace, and an inner helper holding an fd and
# an inotify watch on the files of it -- the exact shape of the sysbox
# fuse of a coder envbox workspace. The fuse fds must be closed on
# restore (their mount is not restored), the dump must not wait for
# the frozen fuse server. Run as root.

set -u

# shellcheck source=test/others/env.sh
[ -f ../env.sh ] && source ../env.sh

# Hide the bind mounts of the environment (docker, etc.) from the
# dumped tree: run everything in a private mount namespace.
if [ "${FUSE_DIND_IN_NS:-}" != "1" ]; then
	exec unshare -m bash -c '
		mount --make-rprivate /
		umount /etc/resolv.conf /etc/hostname /etc/hosts 2>/dev/null
		echo nameserver 127.0.0.1 > /etc/resolv.conf
		echo test > /etc/hostname
		echo 127.0.0.1 localhost > /etc/hosts
		cd "$1" && FUSE_DIND_IN_NS=1 exec bash fuse-dind.sh
	' _ "$(dirname "$0")"
fi

T=$(mktemp -d /tmp/criu-fuse-dind.XXXXXX)
ROOT=""
rm -rf /test/out
trap 'rm -rf "$T"; [ -n "$ROOT" ] && kill "$ROOT" 2>/dev/null || :' EXIT

BACK="$T/backing"
MNT="/mnt/fuse-dind"
COUNTER="$T/counter"
FDSTATUS="$T/fdstatus"

mkdir -p "$BACK"
echo testhost > "$BACK/hostname"

cc $(pkg-config --cflags fuse3) fuse_dind.c -o "$T/fuse_dind" $(pkg-config --libs fuse3) || {
	echo "FAIL: can't compile fuse_dind"
	exit 1
}

"$T/fuse_dind" "$BACK" "$MNT" "$COUNTER" "$FDSTATUS" "$T/initpid" &
ROOT=""
for i in $(seq 1 20); do
	[ -s "$T/initpid" ] && break
	sleep 1
done
ROOT=$(cat "$T/initpid" 2>/dev/null || echo "")
[ -n "$ROOT" ] || {
	echo "FAIL: the wrapped topology did not start"
	exit 1
}

# Wait for the helper to be up: the counter grows and the fuse fd is alive
for i in $(seq 1 20); do
	sleep 1
	N=$(wc -l < "$COUNTER" 2>/dev/null || echo 0)
	[ "$N" -ge 2 ] 2>/dev/null && [ "$(cat "$FDSTATUS" 2>/dev/null)" = "0" ] && break
done
N1=$(wc -l < "$COUNTER" 2>/dev/null || echo 0)
[ "$N1" -ge 2 ] 2>/dev/null || {
	echo "FAIL: the topology did not start (counter=$N1 status=$(cat "$FDSTATUS" 2>/dev/null))"
	exit 1
}
echo "topology up: $N1 ticks, fuse fd alive"

# Like a container runtime does for the restore of a container rootfs:
# the mountpoints of the image mounts are already there
mkdir -p "$T/root"/{proc,sys,dev/pts,dev/shm,dev/mqueue,mnt/fuse-dind,tmp,etc,run}

# The dump must not wait for the frozen fuse server. Like a runtime
# (a cri-proxy pod-level one, e.g.), it runs from the outside of the
# pid namespace of the root task, without --shell-job: the ids of the
# sessions and the groups of the image are the ones of the tree itself.
timeout -k 5 90 $CRIU dump -t "$ROOT" -D "$T" -v4 -o dump.log
RC=$?
[ $RC -eq 0 ] || {
	echo "FAIL: dump rc=$RC (124 = the fuse deadlock)"
	cp -r "$T" /test/out 2>/dev/null
	tail -20 "$T/dump.log" 2>/dev/null
	exit 1
}
grep -q "on a fuse mount is closed on restore" "$T/dump.log" || {
	echo "FAIL: no fuse fd was seen on a fuse mount -- the topology is not faithful"
	exit 1
}
echo "dump ok: fuse fds closed on restore"

# Like a runtime restore (a runc one, e.g.): a fresh pid namespace
# is created for the container, criu runs in it, without --shell-job,
# and the root task of the image (recorded with the pid namespace of
# its own) is forked into a nested one from it. The sleeps stand for
# the processes of the runtime itself living in the same one, and
# the wrapper stays alive like a runtime does: its pid 1 exiting
# would kill the whole pid namespace of the restored tree with it
# (the kernel kills the members of one whose init has exited).
unshare -pf --mount-proc -- bash -c "sleep 300 & sleep 300 & $CRIU restore --root / -D '$T' -v4 -o restore.log -d --pidfile '$T/pid'; echo \$? > '$T/rcriu.rc'; wait" &
for i in $(seq 1 60); do
	[ -s "$T/rcriu.rc" ] && break
	sleep 1
done
RC=$(cat "$T/rcriu.rc" 2>/dev/null || echo 1)
rm -f "$T/rcriu.rc"
RC=$?
[ $RC -eq 0 ] || {
	echo "FAIL: restore rc=$RC"
	cp -r "$T" /test/out 2>/dev/null
	tail -300 "$T/restore.log" 2>/dev/null
	exit 1
}

# The counter keeps growing and the fuse fd is gone
sleep 3
N2=$(wc -l < "$COUNTER" 2>/dev/null || echo 0)
FDERR=$(cat "$FDSTATUS" 2>/dev/null)
[ "$N2" -gt "$N1" ] 2>/dev/null || {
	echo "FAIL: the counter did not grow ($N1 -> $N2)"
	mkdir -p /test/out
	cp -r "$T"/ /test/out/ 2>/dev/null
	exit 1
}
[ "$FDERR" = "9" ] || {
	echo "FAIL: the fuse fd is $FDERR, not EBADF (9)"
	exit 1
}
echo "restore ok: counter $N1 -> $N2, fuse fd EBADF"

kill "$(cat "$T/pid" 2>/dev/null)" 2>/dev/null
echo PASS
