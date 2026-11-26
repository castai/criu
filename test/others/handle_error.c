#include <assert.h>
#include <errno.h>
#include <stdio.h>

#include "../../criu/include/fsnotify_error.h"

int main(void)
{
	assert(fsnotify_error_from_syscall(7, 0) == 7);
	assert(fsnotify_error_from_syscall(-1, ESTALE) == -ESTALE);
	assert(fsnotify_error_from_syscall(-1, 0) == -EIO);
	puts("fsnotify error preservation passed");
	return 0;
}
