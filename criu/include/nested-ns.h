#ifndef __CR_NESTED_NS_H__
#define __CR_NESTED_NS_H__

#include <stdbool.h>
#include <sys/types.h>

#include "images/core.pb-c.h"
#include "images/userns.pb-c.h"

struct pstree_item;
struct ns_desc;
struct ns_id;
struct mount_info;
struct cr_img;

/*
 * Support for user namespaces nested inside the dumped tree, e.g. a
 * docker daemon running containers with their own user namespaces
 * inside a container being checkpointed (docker-in-docker with
 * userns-remap).
 *
 * Everything declared here is only active when the --nested-ns option
 * is given. Without it every hook is a no-op and criu behaves exactly
 * as before, in particular dumping a task in a nested user namespace
 * fails with the "Can't dump nested user namespace" error.
 *
 * The code is split by concern:
 *   nested-ns.c      option, ownership marks on the namespaces, the
 *                    pid/sid/pgid arithmetic of nested pid namespaces
 *   nested-userns.c  uid/gid maps: dump, restore handshake, id views
 *   nested-pstree.c  fixups of the process tree before it is forked,
 *                    the namespaces created by the tasks themselves
 *   nested-mnt.c     mount namespaces assembled in place by the tasks
 *   nested-runtime.c glue for the inner container runtimes (image
 *                    permissions, runc state files)
 *
 * Only one level of nesting below the root task's user namespace is
 * supported: the dump refuses deeper ones.
 */

bool nested_ns_enabled(void);

/*
 * Whether the namespace is owned by a user namespace nested in the
 * one of the root task. Valid on dump after the task ids are collected
 * and on restore after prepare_pstree(). False without the option.
 */
bool nested_ns_owned(struct ns_id *nsid);

/* Whether the task lives in a user namespace nested in the root one. */
bool nested_ns_task_nested(struct pstree_item *item);

/* The same, for a task known by its real pid (dump side). */
bool nested_ns_real_pid_nested(pid_t real);

/*
 * Dump side
 */

/* Whether a nested namespace of this type may be taken into the image. */
bool nested_ns_dump_ok(struct ns_desc *nd);

/*
 * Checks for a task living in a nested user namespace which have to
 * hold for the restore to be possible; marks the namespaces it owns.
 */
int nested_ns_check_task(struct pstree_item *item);

/* Dump the images of the root and of all the nested user namespaces. */
int nested_ns_collect_user_namespaces(void);

/*
 * The pid of a task at the level of the root task's pid namespace, the
 * sid and pgid of it translated the same way, and the pid in its own
 * (innermost) pid namespace. Without the option the fallbacks are
 * returned untouched.
 */
pid_t nested_ns_dump_vpid(pid_t real, pid_t fallback);
int nested_ns_dump_session(pid_t real, int *pgid, int *sid);
pid_t nested_ns_dump_own_pid(pid_t real, pid_t fallback);

/*
 * Restore side
 */

/* Option/image/kernel consistency checks, called before the tree is read. */
int nested_ns_check_restore(bool image_nested_ns, bool has_image_flag);

/*
 * Process tree fixups before the clone flags are derived
 * (re-parenting of the exec-entered tasks) and after them (a single
 * creator per nested user namespace, ownership marks).
 */
void nested_ns_prepare_pstree(void);
void nested_ns_fixup_clone_flags(void);

/* Whether the clone flags of a sub-task with a new user namespace are allowed. */
bool nested_ns_cflags_ok(unsigned long cflags);

/*
 * The pids to request with clone3(set_tid): the one of the task in its
 * own pid namespace and, for the init of a new one, its pid in the
 * namespace of the forking task. Returns the number of entries, 0 when
 * the pid can not be set at all.
 */
int nested_ns_set_tid(struct pstree_item *item, pid_t pid, pid_t *set_tid, int max);

/* Whether the parent of the task can not set its pid (see nested-ns.c). */
bool nested_ns_pid_can_not_be_set(struct pstree_item *item);

/* Whether the vpid of the task can not be used to open its /proc entry. */
bool nested_ns_pid_not_visible(struct pstree_item *item);

/* Whether the pid the task got matches the one it expects. */
bool nested_ns_pid_ok(struct pstree_item *item, pid_t pid);

/* What setsid() has to return for a session leader. */
pid_t nested_ns_expected_sid(struct pstree_item *item);

/* Whether an inherited sid, differing from the dumped one, is fine. */
bool nested_ns_inherited_sid_ok(struct pstree_item *item, pid_t sid);

/*
 * The pgid to set for the task: the dumped one translated into its own
 * pid namespace. Returns false when it can not be set (the group
 * leader lives outside of the pid namespace of the task).
 */
bool nested_ns_pgid(struct pstree_item *item, pid_t *pgid);

/* A full replacement of prepare_userns_creds() with the option. */
int nested_ns_prepare_userns_creds(void);

/* Whether prepare_userns_creds() is needed for this task. */
bool nested_ns_needs_prep_creds(struct pstree_item *item);

/* Parent task: initialize the per-child state before forking it. */
int nested_ns_child_init(struct pstree_item *item, unsigned long clone_flags);

/*
 * Parent task: after forking a child into a new user namespace, fill
 * in its uid and gid maps. real is the pid of the child in the pid
 * namespace of the parent, as returned by clone().
 */
int nested_ns_child_forked(struct pstree_item *item, unsigned long clone_flags, pid_t real);

/* Child task: report the pid, wait for the maps, abort the handshake. */
int nested_ns_child_report(struct pstree_item *item);
/*
 * Root task: move the pid counter of the root pid namespace above every
 * requested pid, so the random pids of the tasks of the inner
 * containers (which their nested user namespace parents can not set)
 * can not collide with them. To be called before any task is forked.
 */
int nested_ns_seed_pid_counter(void);

int nested_ns_child_wait(struct pstree_item *item);
void nested_ns_child_abort(struct pstree_item *item);

/*
 * Translate the ids of the credentials of a task living in a nested
 * user namespace and drop the groups which are not mapped in it.
 */
int nested_ns_fix_task_creds(struct pstree_item *item, CoreEntry *core);

/*
 * Translate an id from the view the images hold (the one of the root
 * task's user namespace) to the view of the user namespace the current
 * task is in. A no-op outside of the nested ones.
 */
void nested_ns_view_id(unsigned int *id, bool is_uid);

/* Child task: restore the namespaces owned by our nested user namespace. */
int nested_ns_child_namespaces(struct pstree_item *item);

/* Whether to skip the setns() into our net or mount namespace. */
bool nested_ns_skip_netns(struct pstree_item *item);
bool nested_ns_skip_mntns(struct pstree_item *item);

/* Whether the mount namespace is assembled by the task entering it. */
bool nested_ns_own_mntns(struct ns_id *nsid);

/* Whether the net namespace is created by the task entering it. */
bool nested_ns_own_netns(struct ns_id *nsid);

/* Whether the root fd of the mount namespace has to come from the fdstore. */
bool nested_ns_use_fdstore(struct ns_id *nsid);

/* Root task: pin the root fds of the nested mount namespaces. */
int nested_ns_pin_roots(void);

/* Child task: fill in the mount namespace of our nested user namespace. */
int nested_ns_child_mntns(struct pstree_item *item);

/*
 * The tmpfs archives of the nested mount namespaces are made for a
 * busybox tar (no GNU sparse format); whether an archive is gzip-ed is
 * detected from its content on restore.
 */
bool nested_ns_tmpfs_plain(struct mount_info *pm);
int tmpfs_img_is_gzip(struct cr_img *img);

/*
 * Runtime glue (nested-runtime.c): make the images readable by the
 * remapped roots of the nested user namespaces for the time of the
 * restore, and update the runc state files at the end of it.
 */
int nested_ns_images_open(void);
void nested_ns_images_restore(void);
void nested_ns_patch_runc_states(void);

/*
 * Internal, between the nested-*.c files.
 */
void nested_ns_mark_owned(void);
int nested_ns_read_userns_img(unsigned int id, UsernsEntry **e);
int nested_ns_join_userns(struct pstree_item *item);

/*
 * Re-create the inner networking (the bridge and the veth pairs of
 * the containers of an inner runtime, e.g. a docker-in-docker) in the
 * network namespace of the container, called by the restore service
 * after the tree is restored. Returns 0 when there is nothing to do.
 */
int nested_ns_restore_inner_network(void);

/*
 * The sysctls of a nested network namespace from its image, applied
 * in the context of the caller (the network namespace of it): used by
 * the restore service for the ones the tasks entering them leave out.
 */
int nested_ns_restore_conf(struct ns_id *ns);

#endif /* __CR_NESTED_NS_H__ */
