#ifndef __CR_NESTED_NS_H__
#define __CR_NESTED_NS_H__

#include <stdbool.h>
#include <sys/types.h>

#include "images/userns.pb-c.h"

struct pstree_item;
struct ns_desc;
struct ns_id;

/*
 * Support for nested user namespaces, e.g. a docker daemon running
 * containers with their own user namespaces inside a container being
 * checkpointed (docker-in-docker).
 *
 * Everything in this file is only active when the --nested-ns option
 * is given. Without it criu behaves exactly as before, in particular
 * dumping a task in a nested user namespace fails with the
 * "Can't dump nested user namespace" error.
 */

bool nested_ns_enabled(void);

/*
 * Dump side
 */

/*
 * Whether a nested namespace of this type may be taken into the
 * image instead of failing with the "Can't dump nested namespace"
 * error. Currently only user namespaces.
 */
bool nested_ns_dump_ok(struct ns_desc *nd);

/*
 * Dump the images of all the user namespaces: the one of the root
 * task, if it has its own one, and all the nested ones, each with its
 * own uid and gid mappings relative to its parent user namespace.
 */
int nested_ns_collect_user_namespaces(void);

/*
 * Checks for a task living in a nested user namespace, which have
 * to hold for the restore to be possible.
 */
int nested_ns_check_task(struct pstree_item *item);

/*
 * Restore side
 */

/*
 * A full replacement of prepare_userns_creds() for the option:
 * entering the user namespace of the restored tree keeps the
 * capabilities, so that a task forking a child in a nested user
 * namespace can write its id maps.
 */
int nested_ns_prepare_userns_creds(void);

/* Whether prepare_userns_creds() is needed for this task. */
bool nested_ns_needs_prep_creds(struct pstree_item *item);

/*
 * Parent task: initialize the per-child state before forking it into
 * a new user namespace.
 */
int nested_ns_child_init(struct pstree_item *item, unsigned long clone_flags);

/*
 * Pin the root fds of the nested mount namespaces into the fdstore,
 * before any task of the tree is forked. To be called from the root
 * task, after the mount namespaces are assembled.
 */
int nested_ns_pin_roots(void);

/*
 * Parent task: after forking a child into a new user namespace, fill
 * in its uid and gid maps.
 */
int nested_ns_child_forked(struct pstree_item *item, unsigned long clone_flags, pid_t pid);

/*
 * Child task: after determining our pid, report it to the parent,
 * which is going to write the maps of our user namespace.
 */
int nested_ns_child_report(struct pstree_item *item);

/*
 * Child task: wait for the parent to write the maps of our user
 * namespace before applying the credentials.
 */
int nested_ns_child_wait(struct pstree_item *item);

/*
 * Child task: restore the content of the namespaces owned by our
 * nested user namespace (e.g. the hostname of our own uts one).
 */
int nested_ns_child_namespaces(struct pstree_item *item);

struct CoreEntry;

/*
 * Translate the ids of the credentials of a task living in a nested
 * user namespace from the view of the dumping criu process into the
 * one of the user namespace of the task.
 */
int nested_ns_fix_task_creds(struct pstree_item *item, struct CoreEntry *core);

/*
 * Strip the CLONE_NEWUSER flag from the tasks which have entered a nested
 * user namespace without creating it, so they are forked without it and
 * join the one of the creator (see nested_ns_child_namespaces).
 */
void nested_ns_fix_exec_userns(void);

/*
 * Child task: wake up the parent, as we are dying before the maps of
 * our user namespace are written.
 */
void nested_ns_child_abort(struct pstree_item *item);

/*
 * Whether to skip the setns() into our network namespace, as we have
 * inherited it from the parent task and may have no capabilities in
 * the user namespace owning it.
 */
bool nested_ns_skip_netns(struct pstree_item *item);

/*
 * Whether the mount namespace is owned by a nested user namespace,
 * i.e. it is assembled by the task which has entered it.
 */
bool nested_ns_own_mntns(struct ns_id *nsid);

/*
 * Whether the task was born in its own mount namespace, owned by
 * its nested user namespace, and has to skip the setns() into one.
 */
bool nested_ns_skip_mntns(struct pstree_item *item);

/*
 * Whether this task has to take the root fd of the given mount
 * namespace from the shared fdstore instead of opening
 * /proc/<pid>/root, as the latter is not allowed from a nested
 * user namespace.
 */
bool nested_ns_use_fdstore(struct ns_id *nsid);

/*
 * Child task: fill in the mount namespace owned by our nested user
 * namespace from the image, in place.
 */
int nested_ns_child_mntns(struct pstree_item *item);

/*
 * Whether the network namespace has to be created by the task which
 * has entered a nested user namespace, and not by the root task.
 */
bool nested_ns_own_netns(struct ns_id *nsid);

/*
 * Whether the clone flags of a sub-task, which include the user
 * namespace one, are allowed.
 */
bool nested_ns_cflags_ok(unsigned long cflags);

#endif /* __CR_NESTED_NS_H__ */
