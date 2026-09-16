#ifndef __CR_CLONE_NOASAN_H__
#define __CR_CLONE_NOASAN_H__

int clone_noasan(int (*fn)(void *), int flags, void *arg);
int clone3_with_pid_noasan(int (*fn)(void *), void *arg, int flags, int exit_signal, pid_t pid);
int clone3_with_pids_noasan(int (*fn)(void *), void *arg, int flags, int exit_signal, pid_t *set_tid,
			    size_t set_tid_size);

#endif /* __CR_CLONE_NOASAN_H__ */
