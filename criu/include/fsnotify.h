#ifndef __CR_FSNOTIFY_H__
#define __CR_FSNOTIFY_H__

#include "fsnotify_error.h"

#include "files.h"

#include "protobuf.h"
#include "images/fsnotify.pb-c.h"

#define KERNEL_FS_EVENT_ON_CHILD 0x08000000

#ifndef INOTIFY_IOC_SETNEXTWD
#define INOTIFY_IOC_SETNEXTWD _IOW('I', 0, __s32)
#endif

void fsnotify_log_handle_attempt(u32 s_dev, u64 i_ino, const char *what);

extern int is_inotify_link(char *link);
extern int is_fanotify_link(char *link);
extern const struct fdtype_ops inotify_dump_ops;
extern const struct fdtype_ops fanotify_dump_ops;
extern struct collect_image_info inotify_cinfo;
extern struct collect_image_info inotify_mark_cinfo;
extern struct collect_image_info fanotify_cinfo;
extern struct collect_image_info fanotify_mark_cinfo;
extern int fsnotify_resolve_pending(int strict);

#endif /* __CR_FSNOTIFY_H__ */
