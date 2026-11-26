#ifndef __CR_FSNOTIFY_ERROR_H__
#define __CR_FSNOTIFY_ERROR_H__

#include <errno.h>

static inline int fsnotify_error_from_syscall(int result, int error)
{
	if (result >= 0)
		return result;
	return error ? -error : -EIO;
}

#endif /* __CR_FSNOTIFY_ERROR_H__ */
