# Nested namespace support (`--nested-ns`) — review

Branch: `filipe/nested-namespace` vs `live-dev` (22 commits, 55 files, +4509/-95).
Core: `criu/nested-ns.c` (2286 lines), `criu/include/nested-ns.h`, plus ~40 hook points in shared code.
Validated by the author on PostgreSQL in docker-in-docker (userns-remap). ZDTM: `test/zdtm/static/userns_nested`.

This document is written to be handed to other models as work instructions. Each finding has an id, a
severity, a `file:line` anchor on this branch, the problem, and the concrete fix to apply. Section 5 is the
ordered task list.

Severity: **C** = will corrupt / crash / leak data, fix before anything else. **H** = wrong restore result in
realistic dind shapes. **M** = gap or fragility, needs a decision or a bounded fix. **L** = cleanup.

---

## 0. Status after the refactoring passes (uncommitted working tree)

Applied on top of the branch. Build clean (no warnings), formatting clean. The finding ids below refer to
sections 2 and 3.

Done:
- **Split** `criu/nested-ns.c` into `nested-ns.c` (option, ownership marks, pid/sid/pgid arithmetic),
  `nested-userns.c` (maps, handshake, id views), `nested-pstree.c` (tree fixups, child namespaces),
  `nested-mnt.c` (in-place mount namespaces, tmpfs), `nested-runtime.c` (image permissions, runc state files).
  One public header `criu/include/nested-ns.h` with the file layout documented at the top (M5).
- **Ownership on the structs** (M3): `struct ns_id.nested`, set by `nested_ns_check_task()` on dump and by
  `nested_ns_prepare_pstree()` on restore; the lazy `own_netns`/`own_mntns` arrays are gone.
  `nested_ns_skip_mntns()` requires the mount namespace to be owned by a nested user namespace (C6).
- **Per-object gating** (M2): netlink and unix in-flight relaxations by the owning task, sockopt / setns /
  hostname tolerance by the current task, tmpfs archive format, mount sharing and `dump_net_ns()` by the
  namespace, iptables of a nested netns tolerated. Still global: cgroupfs inotify watches, nsfs mounts,
  `userns_mount()` skip.
- **`cr-restore.c` hooks** (M4): `nested_ns_set_tid()`, `nested_ns_pid_ok()`, `nested_ns_expected_sid()`,
  `nested_ns_inherited_sid_ok()`, `nested_ns_pgid()`; `restore_sid()` / `restore_pgid()` are the upstream
  bodies plus one call each. Init-pid check restored for the classic path (C11); the `restore_sid` leader
  branch and `set_dump_pidns_level()` are gated (M1 partial).
- **Fixes**: C1 (double free), C2 (images handed to the remapped root once, from the root task, through the
  image dir fd, reverted at the end of the restore; world-readable only as a fallback), C3 (clone return used
  for kill/waitpid), C4 (bounded handshake waits noticing the restore abort), C5 (root-owned tmpfs keeps
  gzip+sparse, nested ones plain, restore sniffs the gzip magic, `--no-same-owner` extraction), C7 (the
  parent task moves a nested child into its cgroups before releasing it, `cgroup2`/`cgroup` mounted in the
  nested mount namespace), C8 (dump refuses non-loopback links of a nested netns unless `--empty-ns net`),
  C9 (pgid translated into the nested pid namespace, dead `skip_setpgid` removed), C10 (exact when the leader
  is in the same pid namespace, tolerant with a warning otherwise), C12 (dump refuses more than one level),
  C13 (`creator_pid` recorded in `userns-<id>.img`), C15 (dump warns about the pids which will be random),
  C16 (`fdstore_get()` rejects negative ids, `pin_roots` failures are hard), C17 (bind sources and the
  rootfs resolved through the parent mount with the same superblock: the old `mi->root`-as-path heuristic
  was wrong for both), C18 partial (mqueue, cgroups, every skipped mount logged), C19a/b/c-logging, C20
  partial (base-256 ids, `K` records, `PATH_MAX` names), C21 (thread creds), C25, C26, C27, C28, C31, C32,
  M6 (`inventory.nested_ns` written on dump and enforced on restore, `--nested-ns` requires
  `clone3(set_tid)`), man page entry (`Documentation/criu.txt`).
- **set_tid rework**: the pids a forking task may request are derived from the user namespace owning the
  pid namespace (`parent_can_set_pid()`), instead of the old "parent in criu's userns" rule; a task of a
  nested user namespace can not keep the outer pid of the init of an inner pid namespace, which the old
  code requested and which the kernel refuses (EPERM).
- **Mount walks**: every walk of a namespace's mounts filters by `mi->nsid` (`for_each_ns_mount`): the
  original walks of `mntinfo_tree` by `->next` crossed into the mounts of the other namespaces.
- **nsfs files** of tasks not visible by their vpid are reopened through criu's `/proc` by real pid.
- **Two unrelated environment fixes** needed to run the tests on a current kernel/distro: UDP-Lite sock-diag
  `ENOENT` tolerated (`sockets.c`, the protocol is gone from the kernel), `pb2dict.py` protobuf-7 shim.

Test (`test/zdtm/static/userns_nested`), which did not run at all before (the branch excluded it from LIVE
CI as "hangs at startup"): fixed five bugs in the test itself (dumpable flag after the id switch, cwd and
ids of the task joining B's namespaces, the worker handshake never released, the entering task never reaped
before the pid namespace teardown, `TEST_EXIT` missing on the success path, waiting for the worker by any
pid since its outer pid is not restorable) and extended it with a process group inside the nested pid
namespace, a bind mount from the parent's tree into B's tmpfs, and a tmpfs file whose owner goes through
the id maps. It passes with and without C/R; the exclusion from the LIVE workflows is reverted.

Second pass, the remaining items:
- C14: kept as designed (the entered task is restored under the creator of the namespace); the dump now
  announces every such task with the parent which loses it, and the man page documents it.
- C22: the uts, ipc and cgroup namespaces unshared by a task without a user namespace of its own are
  filled in / created by that task too (`nested_ns_child_namespaces()` no longer returns early).
- C24: the tolerated hostname failure logs its errno; it restores fine in the test (through usernsd).
- C29, C30: documented in the man page (nsfs mounts and cgroupfs watches are not restored).
- C33: the chroot vs. mount namespace root note is at the top of `nested_ns_child_mntns()`.
- Tests: `userns_nested_deep` (crfail) checks that a user namespace two levels down is refused at dump;
  `FI_NESTED_NS_CHILD_KILL` (fault 7) kills the child before the handshake, the parent notices the abort
  and the restore fails in milliseconds (`zdtm.py run --fault 7 -t zdtm/static/userns_nested -f uns`
  passes: faulted restore fails, the retry succeeds); `test/others/nested-ns/run.sh` checks that an image
  dumped with `--nested-ns` is refused by a restore without it and accepted with it.
- Not done: C34 and the rest of M1 as separate commits (the work is delivered as single commits by
  request).

Verification: `make` in an archlinux container (privileged, host cgroupns), zero warnings; zdtm
`userns_nested -f uns` PASS (with `--nocr` too); env00, pid00, session00, ipc_namespace, utsname, mntns_open
in h/ns/uns PASS; cgroup00, cgroupns PASS; the earlier host-flavor set (pipe00, pipe01, fifo, maps00,
pthread00, zombie00, file_shared, sk-unix01, sk-unix-listen02, socket_listen) PASS. Still untested here: the
real docker-in-docker shape (PostgreSQL) on the target host.

---

## 1. What the branch does (mental model for the reader)

Dump (`--nested-ns`):
- `generate_ns_id()` no longer refuses nested user/uts/net/pid/ipc/cgroup namespaces (`namespaces.c:1335`).
- Every task's vpid/sid/pgid is expressed at the *root task's* pid-namespace level (`proc_parse.c:1088-1215`,
  `cr-dump.c:1180,1189-1212`); the innermost pid is stored as `pstree_entry.own_pid = 1000` (`pstree.c:1849`).
- Each nested userns gets its own `userns-<id>.img` with maps as read from the *dumping criu's* view
  (`nested-ns.c:79-241`). `check_nested_user_ns()` enforces: child userns must be the direct child of the
  parent task's userns; grandchildren may not own net/mnt; no time ns.
- nsfs bind mounts are dropped, mount sharing groups of nested mntns zeroed, cgroupfs inotify watches dumped
  without a path, netlink/unix in-flight queues tolerated.

Restore:
- `prepare_pstree()` re-parents "exec-entered" tasks under the inner init (`nested_ns_fix_exec_pstree`), then
  strips `CLONE_NEWUSER` from all but the "creator" of each nested userns (`nested_ns_fix_exec_userns`).
- `fork_with_pid()` uses `clone3(set_tid[2])` to give the inner init both its inner pid (1) and its outer pid
  (`cr-restore.c:1297-1345`); after fork the parent writes the child's uid/gid maps through criu's `/proc`
  (`nested_ns_child_forked` / `write_child_userns_maps`), child waits on `rsti->userns_maps` futex.
- The child of a nested userns builds its own mntns in place: chroot into the inner rootfs found in the parent
  tree, mounts proc/sysfs/devtmpfs/devpts/tmpfs, replays bind mounts through pre-opened `O_PATH` fds
  (`nested_ns_child_mntns`, `nested-ns.c:1796-2271`), publishes root fd via fdstore. Net ns is unshared by the
  child and filled from image (`net.c:3044`), uts/ipc filled by the child, cgroupns unshared in the child.
- fds crossing net namespaces fall back to the fdstore when the transport socket is unreachable
  (`files.c:1073-1094`).
- `nested_ns_patch_runc_states()` rewrites `init_process_start` in every `/run/**/state.json` after restore.

---

## 2. Modularity and coupling

The mechanism itself is reasonable; what makes it unmergeable is *where* the behaviour lives and how it is
gated. 20 shared files include `nested-ns.h`; there are ~40 `nested_ns_*()` / `nested_ns_enabled()` call
sites, several of which change classic behaviour without the flag.

### M1 (must) Ungated changes to classic paths — split into standalone commits or gate them
Each of these alters restore/dump without `--nested-ns` and needs its own justification or a gate:
- `cr-restore.c:1295-1300` the "First PID in a PID namespace needs to be 1" check was deleted for all modes.
- `cr-restore.c:1410-1432` `restore_sid()` leader branch (`leader->own_ns_pid` is always non-zero after
  `read_one_pstree_item`, so this branch now handles every task).
- `util.c:1013,1035-1036` `userns_view_id()` on every `cr_fchpermat()`; `ipc_ns.c:608,744,891`.
- `mount.c:1909-1910,3423-3424` `nsfd_id/root_fd_id = -1` (was 0) on dump and restore.
- `seize.c:1054` `set_dump_pidns_level()` failure now aborts every dump; `seize.c:741,929,1104` counter guards.
- `compel/src/lib/infect.c:266` ECHILD re-seize.
- `files.c:659-676` O_PATH fifo dumped as regfile (good fix, but separate commit).
- `pipes.c:425`, `tty.c:262`, `pie/restorer.c:1237`, `include/linux/rseq.h`, `namespaces.h` enum rename,
  build flavour (`CASTAI_STATIC`) — unrelated, separate commits.

### M2 (must) Replace scattered `nested_ns_enabled()` policy tweaks with per-object decisions
These are *semantic relaxations* applied to the whole tree once the flag is on, not to nested objects:
`sk-netlink.c:77-88` (drop netlink data), `sk-unix.c:536-548` (drop in-flight write queue), `sockets.c:488`
(sockopt fallback), `sockets.c:1042-1055` (setns failure tolerated), `uts_ns.c:66-76` (hostname failure
tolerated), `filesystems.c:417-470` (tmpfs archive format), `fsnotify.c:232-248,563-577` (cgroupfs watches),
`mount.c:2264-2276` (userns_mount skip), `mount.c:4014-4027` (sharing zeroed for all NS_OTHER mntns),
`net.c:2929`. Rule: decide per `ns_id`/`pstree_item` ("is this object owned by a nested userns?") and keep the
classic error otherwise. Add one helper `bool ns_is_nested(struct ns_id *)` / `task_in_nested_userns(item)`
computed once and stored on the struct.

### M3 (must) Put the nested-ownership facts on the structs, drop the lazy global arrays
`nested-ns.c:1612-1702` (`own_netns`, `own_mntns`, `collect_own_*`) are process-local arrays rebuilt lazily,
O(n) per lookup, never freed, and return nothing if called before clone flags exist. Replace with
`nsid->nested_owner` (userns id, 0 = root) filled in `prepare_pstree_kobj_ids()` right after clone flags are
derived; `nested_ns_own_mntns/netns()` become one-line reads. `ns_id` is shmalloc'd so every task sees it.

### M4 (should) Shrink the `cr-restore.c` diff to a few hook calls
Move the following bodies out of `cr-restore.c` into `nested-ns.c` helpers with classic fallbacks:
- set_tid computation (`cr-restore.c:1297-1345`) → `nested_ns_set_tid(item, pid, set_tid, &n)`.
- expected-pid check (`cr-restore.c:1512-1537`) → `nested_ns_pid_ok(item, pid)`.
- sid/pgid logic (`cr-restore.c:1493-1551,1566-1620`) → `nested_ns_expected_sid()`, `nested_ns_pgid()`; the
  two identical "nested pidns inherits init sid" blocks must become one.

### M5 (should) Split `nested-ns.c` by concern
- `nested-userns.c`: map parsing/writing, id translation (one `struct idmap` with `map_up/map_down`; today
  there are three walkers: `translate_lower_ids`, `id_mapped_in_ns`, `userns_view_id`).
- `nested-pstree.c`: exec re-parenting, creator selection, pid visibility.
- `nested-mnt.c`: `pin_roots`, `child_mntns`, tmpfs; deduplicate rootfs discovery (`nested-ns.c:748-773` and
  `1921-1976` are the same search) into `nested_rootfs_path(nsid, pnsid, buf)`.
- Product glue out of criu core: `nested_ns_patch_runc_states()` and `nested_ns_chmod_images()` are runc /
  deployment concerns. Move to a `--action-script post-restore` hook or a `criu/plugin.c` plugin
  (`CR_PLUGIN_HOOK__RESUME_DEVICES_LATE` runs after all tasks exist). Upstream will not take them.

### M6 (should) Image / option hygiene
- Record `nested_ns` in `inventory.img` (new optional field, high number) and refuse restore when the flag on
  the command line differs from the image (needed because of C5).
- Add `--nested-ns` to `Documentation/criu.txt` and `criu/crtools.c` already has usage text; add to
  `cr-check.c` a feature check: requires `kdat.has_clone3_set_tid` (see C23).
- `pstree.proto`/`rpc.proto` field 1000: fine; also mirror into `lib/pycriu` (done) and `crit` decode test.

---

## 3. Correctness

### C1 (C) Double free in `write_child_userns_maps()` — `nested-ns.c:665-670`
`goto err_free_pe` frees `pe`, falls through to `err:` which frees `pe` again (`pe` is not NULLed).
Triggered whenever `translate_lower_ids()` fails (an id of the nested map not covered by the parent map).
Fix: delete the `err_free_pe` label, keep the single `if (pe) free` in `err:`.

### C2 (C, security) Image files made world-readable — `nested-ns.c:674-702`, called from `:1005`
`nested_ns_chmod_images()` does `chmod o+r` on every file under `opts.imgs_dir` (pages-*.img contain process
memory: credentials, keys). It runs in the parent for every child forked with `CLONE_NEWUSER`, and never
reverts. Fix: (a) do it once, in the root task, before forking; (b) do not use `o+r`: `fchownat()` the files
to the kuid/kgid that uid 0 of the *innermost* nested userns maps to (first extent `lower_first`, composed
through the parent map) with mode 0400, or add a POSIX ACL for that kuid; (c) restore original mode/owner in
the root task after `CR_STATE_RESTORE`; (d) log at `pr_warn` that image permissions were changed. If the
deployment already runs with a dedicated image directory, prefer the action-script route (M5).

### C3 (H) Wrong pid killed on map-write failure — `nested-ns.c:1020`, `cr-restore.c:1370`
`nested_ns_child_forked(item, flags, pid)` receives `vpid(item)` and calls `kill(pid, SIGKILL)`. When the child
was forked with a random pid (`pid_not_set`) or as an inner init (`set_tid[1]` only equals vpid when the parent
is in the root pidns), `vpid` is not the child's pid in the parent's pidns → may SIGKILL an unrelated restored
task. Fix: pass `ret` (the `clone3` return value) and use it for `kill`/`waitpid`.

### C4 (H) Parent hangs forever if the child dies before reporting — `nested-ns.c:1012`, `:1251`
`futex_wait_until(&userns_maps, 1)` has no abort path when the child is killed by a signal (OOM, SIGKILL,
crash before reaching `err:`); `nested_ns_child_abort()` only runs on the child's error path. Same for the child
waiting for `2` if the parent dies. Fix: create a `pidfd_open(ret)` in the parent and poll it together with the
futex (or `waitpid(ret, WNOHANG)` in a loop with `futex_wait` timeouts); in the child, watch the parent with
`prctl(PR_SET_PDEATHSIG)` or check `getppid()` in the loop.

### C5 (H) Global tmpfs image format change; images not interchangeable — `filesystems.c:417-470`
With the flag, **all** tmpfs archives (root mntns included) are written without `--gzip` and `--sparse`; restore
picks the format from the flag, not from the image. Effects: an image dumped with `--nested-ns` cannot be
restored without it (and vice versa); large sparse files in tmpfs (e.g. `/dev/shm` of postgres,
`/tmp` scratch) balloon the image. Fix: keep GNU options for tmpfs owned by the root userns; for nested ones
drop only `--sparse` (busybox tar supports `-z`); on restore sniff the gzip magic (`1f 8b`) on `img_raw_fd`
instead of the flag; record `nested_ns` in inventory (M6).

### C6 (H) Any non-root mntns is treated as nested — `nested-ns.c:1704-1724`, `pstree.c:952,990`
`nested_ns_skip_mntns()` returns true for every task whose `mnt_ns_id != root_item's`, regardless of userns.
With the flag on, a classic sub-mount-namespace inside the *same* userns (systemd `PrivateTmp`, `unshare -m`,
snapd, some CI runners) keeps `CLONE_NEWNS` in its clone flags, skips `restore_task_mnt_ns()`, and enters the
chroot/essential-mount path of `nested_ns_child_mntns()` while the root task also assembles that mntns
normally. Fix: return true only when the mntns is owned by a nested userns (`nsid->nested_owner != 0`, M3) or
when the task's `user_ns_id != root_item->ids->user_ns_id`.

### C7 (H) Inner container cgroups not restored — `cgroup.c:107-108`, `nested-ns.c:1526-1543,2112-2157`
The task creating the nested userns skips `restore_task_cgroup()`; its children share its `cg_set` and are
"inherited". Result: the whole inner container lands in the containerd-shim's cgroup; the inner cgroup
directories are re-created (from `cgroup.img`) but stay empty. Consequences after restore: `docker stop/kill`
of the inner container (runc kills by `cgroup.procs`), memory/cpu limits, `docker stats`, cgroup-based OOM
handling are all broken or silently no-ops; the unshared cgroupns has the shim's cgroup as root. Also the inner
`/sys/fs/cgroup` mount is never created (no `FSTYPE__CGROUP2` case in the essential-mount switch), so
Go/Java runtimes reading cgroup limits inside the inner container see ENOENT.
Fix: (a) move the cgroup step to the *parent* task (which is in the outer userns and owns the delegated
subtree): in `nested_ns_child_forked()` before releasing the futex to `2`, write the child's real pid into
`cgroup.procs` of the path of `rsti(child)->cg_set` (reuse `move_in_cgroup()` with an explicit pid, add a
`pid` parameter); (b) keep `unshare(CLONE_NEWCGROUP)` in the child after that so the ns root is the right
cgroup; (c) add a `FSTYPE__CGROUP2` (and v1 `FSTYPE__CGROUP`) case mounting `cgroup2` at `mi->ns_mountpoint`
with `mi->sb_flags` (nsroot semantics give the inner view automatically).
Add a zdtm check: `/proc/self/cgroup` of the inner task equals its dump value.

### C8 (H) Inner networking is not restored — `net.c:2929-2935,3044-3115`
With `--empty-ns net` the nested netns image is empty: only `lo` is brought up. Without it, the nested netns
has a veth whose peer is in the outer netns → `__restore_links()` creates fewer links than dumped →
`nrcreated != nrlinks` → restore fails. Either way inner containers have no bridge connectivity after restore
(only 127.0.0.1). Immediate fix: fail at **dump** time with a clear message when a nested netns contains any
link other than `lo` and `--empty-ns net` is not given, so the failure is not discovered at restore.
Proper fix (later): create veth pairs from the root task (it has caps in both user namespaces) and move one
end with `IFLA_NET_NS_FD` into the nested netns; requires the child to publish its netns fd into the fdstore
(`nsid->net.nsfd_id`) and the root task to wait for it (new stage or futex per nested netns). Also note
`nsid->net.nsfd_id` is never set for nested netns, so `set_netns()` (`sockets.c:1038`) does `fdstore_get(0)`
and the `setns` failure is then swallowed by the new `pr_warn` path — sockets of a *different* task in that
netns would be restored in the wrong netns silently. Set `nsfd_id` in `nested_ns_child_netns()`.

### C9 (H) Process groups inside nested pid namespaces are not restored — `cr-restore.c:1566-1569`
`restore_pgid()` returns early for every task in a nested pidns. Any pgid set inside the inner container is
lost: shells with job control, `supervisord`, `tini -g`, `pg_ctl` wrappers, anything that calls `setpgid`.
Fix: translate: `leader = pstree_item_by_virt(current->pgid)`; `my_pgid = leader->own_ns_pid` when `leader`
is in the same pidns as `current`, keep the `pgrp_set` futex handshake, call `setpgid(0, my_pgid)`. Only skip
when the leader is outside the current pidns (then the pgid is not representable and was inherited by fork).
Delete the now-dead `skip_setpgid` block (`cr-restore.c:1602-1616`), which today only fires for a root task
with `CLONE_NEWPID` and skips its `setpgid` under the flag.

### C10 (M) Session check weakened — `cr-restore.c:1410-1445`
Any nested-pidns task whose inherited sid is `1` passes. That accepts wrong sessions, notably the exec-entered
tasks re-parented by C14 (their real sid is the shim's session). Fix: compute the expected value exactly:
leader in the same pidns → `leader->own_ns_pid`; leader outside the pidns → `getsid()` must return `0`
(not visible) and the task must have been forked by something in that session; otherwise error.

### C11 (M) Removed init-pid check — `cr-restore.c:1295-1300`
Re-add for the non-nested branch (`if (!nested_ns_enabled() && !external_pidns && pid != INIT_PID) error`),
and in the nested branch check `item->own_ns_pid == INIT_PID` for `CLONE_NEWPID` tasks.

### C12 (M) Only two userns levels are actually supported, deeper nesting is not rejected
`translate_lower_ids()` (`nested-ns.c:434`) and `userns_view_id()` (`util.c:1013`) assume the *parent*
userns's lower ids are in the dumping criu's view, which is only true when the parent userns is the root one.
dind-in-dind, or rootless podman inside the inner container, silently gets wrong maps / wrong file owners.
Fix now: at dump, walk `NS_GET_PARENT` from each nested userns to the root task's userns and refuse depth > 1
(relative to root) with a clear error. Later: compose maps top-down (translate each level's lower ids into its
parent's view before using it) and cache the composed map per userns id.

### C13 (M) "Creator = lowest vpid" heuristic — `nested-ns.c:884-926`
Breaks on pid wrap-around, or when the creating task exited and a later-entered task has the lowest pid.
Fix: decide at dump. `ns_id->ns_pid` is the first task seen in pstree walk order (parents before children);
store it as `creator_pid` in `userns-<id>.img` (optional field, high number) together with the task's
start time, and use it on restore. Fall back to the heuristic only for images without the field.

### C14 (M) Exec-entered tasks are re-parented under the inner init — `nested-ns.c:821-882`
A `docker exec` process at dump time is a child of the shim/runc-exec; after restore it is a child of the
inner init. The shim's `wait4(pid)` returns `ECHILD` → the exec session is torn down; the process is reaped by
the inner init (or leaks as a zombie if that init does not reap); `getppid()` changes. `prepare_pstree_ids()`
runs after the re-parent so session helpers are derived from the fake tree (interacts with C10).
Decision needed: (a) accept, document as "in-flight execs are terminated", and make dump print a warning
listing such tasks; or (b) implement properly: fork from the real parent (outer userns has caps over the
child userns), `setns()` user+mnt+net+ipc+uts+cgroup, and enter the pidns through a helper like the
`external_pidns` path in `fork_with_pid()`. (a) is fine for the PostgreSQL use case.

### C15 (M) Silent random pids — `nested-ns.c:1411-1457`, `cr-restore.c:1301-1303`
Tasks forked by a nested-userns task whose pidns is owned by an ancestor userns (`unshare -U` daemons,
rootless tools, dind without `--userns-remap` where dockerd unshares userns per container but not pidns)
are restored with random pids; the parent's `waitpid(orig)` fails. This is decided at restore and only warned.
Fix: detect at dump (same walk as C12) and either fail with a clear message or require an explicit opt-in
(`--nested-ns-random-pids`); print the affected pids.

### C16 (M) `fdstore_get(-1)` returns a random fd — `mount.c:3958`, `nested-ns.c:775-792`, `fdstore.c`
`root_fd_id` now starts at -1. `nested_ns_pin_roots()` continues on failure (rootfs not found, open fails,
fdstore_add fails) leaving -1; `mntns_get_root_fd()`'s `!ns_populated` branch then calls `fdstore_get(-1)`,
`SO_PEEK_OFF=-1` disables the offset and `MSG_PEEK` returns the *first* stored fd. Paths of that mntns resolve
against an arbitrary directory. Fix: `fdstore_get()` must reject `id < 0`; `pin_roots` failures must be hard
errors (or explicitly set the ns as "assembled by child, not pinned" and make `mntns_get_root_fd` fail
loudly).

### C17 (M) Bind-mount sources resolved by the wrong path — `nested-ns.c:1995-2024`
`mi->root` is a path inside the *source superblock*, not in the parent mntns; `stat(mi->root)` almost never
hits, and the fallback `stat(mi->ns_mountpoint)` binds the **outer** container's `/etc/hosts`, `/etc/hostname`,
`/etc/resolv.conf` (and any `-v` volume whose mountpoint exists in the outer tree) into the inner container.
Fix: find in `pnsid->mnt.mntinfo_tree` the mount with the same `s_dev` whose `root` is a prefix of `mi->root`
and open `<pmi->ns_mountpoint>/<mi->root minus pmi->root>`; if none, fail (do not guess). Add a zdtm check
comparing the inode of a bound file before/after.

### C18 (M) Essential-mount switch drops everything else silently — `nested-ns.c:2112-2157`
No `cgroup2` (C7), no `mqueue`, no `nsfs`, no `overlay` sub-mounts, no `fuse`. Volumes are only handled if
they are bind mounts (subject to C17). At minimum log at `pr_warn` each mount skipped with fstype and
mountpoint, and add `mqueue` + `cgroup2`. Consider reusing the standard mount code by running
`do_mount_one()` for the nested tree from inside the chroot: the mount images already contain everything.

### C19 (M) `nested_patch_state_json()` — `nested-ns.c:1079-1240`
(a) fd leak: `if (!st) return 0;` at `:1119-1122` skips `close(fd)`.
(b) No `ftruncate(fd, len)` after the rewrite: when the new start time has fewer digits than the old one the
file keeps trailing bytes → invalid JSON → runc refuses every later operation on that container.
(c) `chmod o+x` on every component of the `rootfs` path taken from a file inside the restored tree, as outer
root, permanently (`:1140-1165`). Side effect on the host storage layout; path is attacker-controlled by the
inner container's runtime state.
(d) Walks all of `/run` on every restore, mounts a fresh procfs under the container's `/tmp` (`mkdtemp`),
leaves the directory if `umount` fails.
Fix a/b now. Move the whole function to a post-restore action script or plugin (M5); pass the pid→starttime
mapping explicitly instead of walking `/run`.

### C20 (M) Hand-rolled tar parser for tmpfs ownership — `nested-ns.c:1281-1362`
Long names > 255 bytes truncated (`lname[256]`), no `K` (long link) records, unchecked short reads, ids
≥ 2097152 (GNU base-256 encoding, high bit set) parse as 0 → files chowned to root. Better: avoid the fixup
entirely by dumping nested tmpfs from *inside* the nested userns (`cr_system_userns(..., ns->ns_pid)` with the
nested task's pid) so the archive already carries ids in the nested view, and let tar restore ownership.

### C21 (L) Only the leader thread's creds are validated — `nested-ns.c:571-594`
Other threads' `thread_core->creds` are not filtered; a thread with an unmapped supplementary group fails
`setgroups` in the restorer. Loop over all thread cores.

### C22 (L) Tasks that unshared only uts/ipc/cgroup (same userns) get empty namespaces
`nested_ns_dump_ok()` allows them at dump; `nested_ns_child_namespaces()` returns early without
`CLONE_NEWUSER` (`nested-ns.c:1488-1507`), so ipc objects are lost and the cgroupns is never created. Either
restrict `nested_ns_dump_ok()` to "new userns at this task" + inherited, or handle these too.

### C23 (L) Requires clone3 set_tid but does not say so — `cr-restore.c:1278,1297`
`own_ns_pid` handling exists only in the clone3 branch; the legacy `ns_last_pid` path produces wrong pids
in nested pid namespaces. Add to `cr-check.c` and to restore start: `--nested-ns` requires
`kdat.has_clone3_set_tid` (kernel ≥ 5.5).

### C24 (L) Hostname failure is masked — `uts_ns.c:66-76`
The "no permission" explanation is not established: the task filling the uts ns is uid 0 with full caps in the
owning userns, and `sysctl_op()` (`sysctl.c`) only goes through `usernsd` when the root task is in a userns.
Reproduce with the zdtm test, find the failing shape (likely the joined/exec task, or a uts ns owned by the
parent userns), fix it, and remove the warn-and-continue.

### C25 (L) `set_dump_pidns_level()` ungated and fatal — `seize.c:1054`. Gate on the flag or make it
non-fatal (fallback to innermost pid as before).

### C26 (L) `userns_view_id()` opens `/proc/self/{uid,gid}_map` per call — `util.c:1013`
Runs for every chown / ipc object in every restore. Cache the parsed map per process (it cannot change after
`prepare_userns_creds`), gate on the task being in a nested userns.

### C27 (L) `nested_ns_fix_task_creds()` re-reads `userns-<id>.img` per task — cache per userns id.

### C28 (L) compel ECHILD re-seize can loop — `compel/src/lib/infect.c:266`
If `compel_interrupt_task()` succeeds but `wait4` keeps returning `ECHILD` (task is a tracee of another thread
or a different process), `goto try_again` repeats. Bound to one retry. Also `seize.c` `processes_to_wait > 0`
guards hide the counter mismatch: increment the counter for fallback-seized tasks instead.

### C29 (L) `nsfs` mounts dropped at dump — `proc_parse.c:1911-1916`
`/run/docker/netns/<id>` files vanish; inner `docker network connect/disconnect`, `docker exec` into containers
on user-defined networks may fail. Document; interacts with C8.

### C30 (L) cgroupfs inotify watches dropped — `fsnotify.c:232-248,563-577`
containerd-shim's OOM/event watchers for inner containers stop delivering. Document.

### C31 (L) `dump_nested_userns()` leaks `e.uid_map` when the gid parse fails — `nested-ns.c:173-175`.

### C32 (L) `restore_sid()` uses `pr_perror` without an errno — `cr-restore.c:1505`. Use `pr_err`.

### C33 (L) `nested_ns_child_mntns()` small issues: `mkdirpat()` result ignored (`:2110,2183`);
`MAX_BIND_FDS 64` truncates silently (`:1995`); `bind_fds` leak on early `return -1` after they are opened
(process exits, acceptable but close them); `chroot` instead of `pivot_root` means `/proc/<pid>/root != "/"`
for inner tasks — `__mntns_get_root_fd()` (`mount.c:3900`) would reject them if ever reached; document why
chroot is required (locked mounts) at the top of the function.

### C34 (L) O_PATH fifo dumped as regfile — `files.c:659-676`
Correct, but ungated and generic: standalone commit with a zdtm test (`fifo` opened `O_PATH`).

---

## 4. Leaks and side effects (consolidated)

Memory / fd leaks:
- C1 double free (`nested-ns.c:665-670`).
- C19a fd leak (`nested-ns.c:1119`).
- C31 `e.uid_map` leak on error (`nested-ns.c:173`).
- `own_netns` / `own_mntns` arrays never freed (`nested-ns.c:1612,1660`) — process lifetime, fix via M3.
- `nested_ns_child_netns()`: `nsid->net.nlsk` leaks on error paths (`net.c:3096-3110`); `ns_fd` kept open by
  design (matches classic code).
- fdstore growth: every cross-netns fd (`files.c:1084`), every pinned root (`nested-ns.c:787`), every child
  root (`:2250`) adds an fd to the fdstore socket queue for the life of the restore. Bounded by task/fd count;
  acceptable, document.

Persistent side effects on the host / container filesystem:
- C2 image files chmod `o+r` (never reverted).
- C19c `chmod o+x` on rootfs path components (never reverted).
- C19 `state.json` rewritten in place; `/tmp/.criu-proc-XXXXXX` dir in the restored root mntns if umount fails.
- C20 `fchownat` over every extracted tmpfs entry (intended, but note it also chowns pre-existing entries
  with the same name if the archive is partial).

Behavioural side effects on non-nested objects when the flag is on (all from M1/M2):
- all tmpfs archives uncompressed and non-sparse (C5);
- netlink socket queues dropped, unix in-flight write queues dropped tree-wide;
- `SO_*BUFFORCE` fallback tree-wide (buffer sizes silently capped by `net.core.*mem_max`);
- any non-root mntns takes the chroot path (C6);
- `restore_pgid` skipped for root task with `CLONE_NEWPID` (C9);
- every `mntns_get_root_fd()` goes through the fdstore (socket round trip + `install_service_fd`) once a
  `root_fd_id` exists (`mount.c:3958`), for all namespaces, not only nested ones;
- `nftw()` over the image dir per nested fork and over `/run` per restore.

---

## 5. Task list for other models (do in this order)

Each task: branch from `filipe/nested-namespace`, one commit per task, run
`sudo ./test/zdtm.py run -t zdtm/static/userns_nested -f uns` plus `zdtm/static/env00`, `userns00`,
`mntns_open`, `pid00`, `cgroup00` without `--nested-ns` to prove classic behaviour is untouched. Use the
`file:line` anchors above; do not widen scope beyond the task.

1. **Crash/security fixes (C1, C2, C3, C4, C19a/b, C31, C16).** Small, isolated, no design decisions. For C2
   implement the chown-to-mapped-uid + revert variant, once, in the root task. For C4 use `pidfd_open` +
   `poll` on the parent side.
2. **Gate or split ungated changes (M1).** Produce separate commits for: O_PATH fifo (C34), rseq/enum/build
   fixes, `restore_sid` leader branch gating, `userns_view_id` gating + caching (C26), `set_dump_pidns_level`
   gating (C25), init-pid check restoration (C11), seize/compel counter fixes (C28).
3. **Ownership facts on structs (M3) and `skip_mntns` fix (C6).** Add `nsid->nested_owner`, compute in
   `prepare_pstree_kobj_ids()`, delete the lazy arrays, rewrite `nested_ns_own_*`, `nested_ns_skip_mntns`,
   `nested_ns_use_fdstore` on top of it. Then scope the M2 relaxations per object.
4. **Cgroups (C7).** Parent-side `move_in_cgroup(se, pid)`, cgroup2 essential mount, zdtm assertion on
   `/proc/self/cgroup`.
5. **pgid/sid inside nested pidns (C9, C10).** Translate through `own_ns_pid`, exact expectations, delete dead
   `skip_setpgid`. Add a zdtm shape: inner task does `setpgid` on a child, verify after restore.
6. **Dump-time validation (C8, C12, C15, C23, C13).** Depth check via `NS_GET_PARENT`; nested netns link
   check unless `--empty-ns net`; random-pid detection; clone3 requirement in `cr-check`; record
   `creator_pid` in `userns-<id>.img`. Every refusal must name the pid and the reason.
7. **Mount correctness (C17, C18, C20, C33).** Correct bind-source resolution; warn per skipped mount; add
   mqueue; dump nested tmpfs from inside the nested userns and delete the tar parser; tmpfs format sniffing
   (C5) and inventory flag (M6).
8. **Product glue out of core (M5, C19).** Move runc state patching and image chmod to an action script /
   plugin; fix `ftruncate`; drop the `/run` walk in favour of explicit paths.
9. **Refactor `cr-restore.c` hooks (M4) and split `nested-ns.c` (M5).** Pure moves, no behaviour change;
   diff of `cr-restore.c` should shrink to ~10 hook calls.
10. **Decide C14** (exec re-parenting) and C24 (hostname) with the author; then documentation
    (`Documentation/criu.txt`, a `docs/nested-ns.md` with the supported shapes and the limitations list:
    2-level userns only, inner networking, in-flight execs, nsfs mounts, cgroupfs watches).

Test coverage to add along the way (zdtm `userns_nested` currently covers the userns/pid/mnt shapes and an
exec-entering task): cgroup membership, pgid inside nested pidns, bound `/etc/hosts` identity, tmpfs file
ownership with remapped ids, veth in nested netns refused at dump, 3-level nesting refused at dump, image
dumped with the flag restored without it (must fail cleanly), child killed during map handshake (must not
hang: run restore under `timeout`).
