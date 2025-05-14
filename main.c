#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include "net.h"
#include <linux/slab.h>  // kmalloc
#include <linux/mutex.h>
#include <linux/file.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("hook read");
MODULE_AUTHOR("bobo");

#define ARRAY_SIZE 1024
#define MAX_STRING_LENGTH 1024
struct mutex my_mutex;
struct mutex my_mutex1;
char **program_list;
char **file_list; 


void ** sys_call_table;

asmlinkage int (*org_write) (unsigned int, const char __user *, size_t);
asmlinkage int (*org_open) (const char __user *, int, umode_t);
asmlinkage int (*org_unlink) (const char __user *);
asmlinkage int (*org_unlinkat) (int, const char __user *, int);
int alloc_list(void)
{
	int i;

	// 申请内存：创建一个包含5个字符串指针的数组
	program_list = kmalloc(ARRAY_SIZE * sizeof(char *), GFP_KERNEL|__GFP_ZERO);
	if (!program_list) {
		printk(KERN_ALERT "Failed to allocate memory for string array\n");
		return -ENOMEM;
	}

	// 为每个字符串分配内存
	for (i = 0; i < ARRAY_SIZE; i++) {
		program_list[i] = kmalloc(MAX_STRING_LENGTH, GFP_KERNEL|__GFP_ZERO);
		if (!program_list[i]) {
			printk(KERN_ALERT "Failed to allocate memory for string %d\n", i);
			// 释放已分配的内存
			while (i-- > 0)
				kfree(program_list[i]);
			kfree(program_list);
			return -ENOMEM;
		}
		//       snprintf(program_list[i], MAX_STRING_LENGTH, "String %d", i); // 填充字符串
		printk(KERN_INFO "%s\n", program_list[i]);
	}
	return 0;
}

int alloc_file_list(void)
{
	int i;

	// 申请内存：创建一个包含5个字符串指针的数组
	file_list = kmalloc(ARRAY_SIZE * sizeof(char *), GFP_KERNEL|__GFP_ZERO);
	if (!file_list) {
		printk(KERN_ALERT "Failed to allocate memory for string array\n");
		return -ENOMEM;
	}

	// 为每个字符串分配内存
	for (i = 0; i < ARRAY_SIZE; i++) {
		file_list[i] = kmalloc(MAX_STRING_LENGTH, GFP_KERNEL|__GFP_ZERO);
		if (!file_list[i]) {
			printk(KERN_ALERT "Failed to allocate memory for string %d\n", i);
			// 释放已分配的内存
			while (i-- > 0)
				kfree(file_list[i]);
			kfree(file_list);
			return -ENOMEM;
		}
		// snprintf(file_list[i], MAX_STRING_LENGTH, "String %d", i); // 填充字符串
		printk(KERN_INFO "%s\n", file_list[i]);
	}
	return  0;
}

void free_file_list(void)
{
	int i;

	// 在模块退出时释放内存
	if (file_list) {
		for (i = 0; i < ARRAY_SIZE; i++) {
			kfree(file_list[i]);  // 释放每个字符串
		}
		kfree(file_list);  // 释放数组本身
	}

}
void free_list(void)
{
	int i;

	// 在模块退出时释放内存
	if (program_list) {
		for (i = 0; i < ARRAY_SIZE; i++) {
			kfree(program_list[i]);  // 释放每个字符串
		}
		kfree(program_list);  // 释放数组本身
	}

}

bool check(char* run_program, char* file, char** program_list, char** file_list) {

	bool program_found = false;
	int i = 0;
	int j = 0;
	bool need_check_file = false;
	//printk(KERN_INFO "check process %s file %s\n", run_program, file);
	mutex_lock(&my_mutex);
	// 遍历 file_list 查找 file 
	// bobo over array? 
	for (j = 0; file_list[j] != NULL &&  j < ARRAY_SIZE; j++) {
	//	printk(KERN_INFO "check protect file %s with file %s\n", file_list[j], file);
		if (strcmp(file_list[j], file) == 0) {
			need_check_file = true;
			break;
		}
	}

	if (!need_check_file) 
	{
		mutex_unlock(&my_mutex);
		return false;}

	// 遍历 program_list 查找 run_program
	for (i = 0; program_list[i] != NULL && i < ARRAY_SIZE; i++) {
		if (strcmp(program_list[i], run_program) == 0) {
			program_found = true;
			break;
		}
	}

	// 如果不在白名单里面
	if (!program_found) {
		mutex_unlock(&my_mutex);
		return true;
	}

	mutex_unlock(&my_mutex);
	return false;  // 没有找到对应的 file
}
static struct file* my_get_task_exe_file(struct task_struct *ctx)
{
	struct file *exe_file = NULL;
	struct mm_struct *mm;

	if(unlikely(!ctx))
		return NULL;

	task_lock(ctx);
	mm = ctx->mm;

	if(mm && !(ctx->flags & PF_KTHREAD))
	{
		rcu_read_lock();

		exe_file = rcu_dereference(mm->exe_file);
		if(exe_file && !get_file_rcu(exe_file))
			exe_file = NULL;

		rcu_read_unlock();
	}

	task_unlock(ctx);

	return exe_file;
}
asmlinkage int new_unlink(const char __user *filename)
{
	printk(KERN_INFO "bobo unlink\n");

	char buf[1024];
	copy_from_user(buf, filename, sizeof(buf)-1);
	buf[sizeof(buf)-1] = 0;

	char *res = NULL;
	struct file *fp_executable = my_get_task_exe_file(get_current());
	if(fp_executable == NULL)
	{
		printk(KERN_INFO "no file\n");
		return (*org_unlink)(filename);
	}
	char exe_path[256];
	memset(exe_path, 0x0, 256);
	if(IS_ERR(res = d_path(&fp_executable->f_path, exe_path, 256)))
	{
		return (*org_unlink)(filename);
	}

	if (check(res, buf, program_list ,file_list))
	{
		printk(KERN_INFO "bobo block unlink cmd %s  file %s\n", res, buf);
		return -EINVAL;
	}

	return (*org_unlink)(filename);
}

asmlinkage int new_unlinkat(int fd, const char __user *filename, int flag)
{
	printk(KERN_INFO "bobo unlinkat\n");
	char buf[1024];
	copy_from_user(buf, filename, sizeof(buf)-1);
	buf[sizeof(buf)-1] = 0;

	char *res = NULL;
	struct file *fp_executable = my_get_task_exe_file(get_current());
	if(fp_executable == NULL)
	{
		printk(KERN_INFO "no file\n");
		return (*org_unlinkat)(fd, filename , flag);
	}
	char exe_path[256];
	memset(exe_path, 0x0, 256);
	if(IS_ERR(res = d_path(&fp_executable->f_path, exe_path, 256)))
	{
		return (*org_unlinkat)(fd, filename , flag);
	}

	if (check(res, buf, program_list ,file_list))
	{
		printk(KERN_INFO "bobo block unlinkat cmd %s  file %s\n", res, buf);
		return -EINVAL;
	}

	return (*org_unlinkat)(fd, filename , flag);

}
asmlinkage int new_open(const char __user * filename, int flags, umode_t mode)
{
	char buf[1024];
	copy_from_user(buf, filename, sizeof(buf)-1);
	buf[sizeof(buf)-1] = 0;
	char *res = NULL;
	struct file *fp_executable = my_get_task_exe_file(get_current());
	if(fp_executable == NULL)
	{
		printk(KERN_INFO "no file\n");
		return (*org_open)(filename, flags, mode);
	}
	char exe_path[256];
	memset(exe_path, 0x0, 256);
	if(IS_ERR(res = d_path(&fp_executable->f_path, exe_path, 256)))
	{
		return (*org_open)(filename, flags, mode);
	}
	if (flags & O_TRUNC)
	{
		printk(KERN_INFO "bobo %s open %s with O_TRUNC\n", res, buf);
		if (check(res, buf, program_list ,file_list))
		{
			printk(KERN_INFO "bobo block cmd %s  file %s\n", res, buf);
			send_netlink_msg(1, get_current()->pid, res,buf);
			return -EINVAL;
		}
		else
			return (*org_open)(filename, flags, mode);
	}


	if ((flags & O_WRONLY)  || (flags & O_RDWR))
	{
		//printk(KERN_INFO "bobo %s open %s with write\n", res, buf);
		if (check(res, buf, program_list ,file_list))
		{
			printk(KERN_INFO "bobo block cmd %s  file %s\n", res, buf);
			send_netlink_msg(1, get_current()->pid, res,buf);
			return -EINVAL;
		}
		else
			return (*org_open)(filename, flags, mode);
	}
	return (*org_open)(filename, flags, mode);
}
asmlinkage int new_write (unsigned int fd, const char __user * buf, size_t len)
{

	mutex_lock(&my_mutex1);
	struct file *file;
	char *res = NULL;
	char path[PATH_MAX] = {0};
	struct file *fp_executable = my_get_task_exe_file(get_current());
	if(fp_executable == NULL)
	{
		printk(KERN_INFO "no file\n");
		mutex_unlock(&my_mutex1);
		return (*org_write)(fd, buf, len); // Do not call exit handler
	}
	char exe_path[256];
	memset(exe_path, 0x0, 256);
	if(IS_ERR(res = d_path(&fp_executable->f_path, exe_path, 256)))
	{
		printk(KERN_INFO "bobo no exe\n");
		mutex_unlock(&my_mutex1);
		return (*org_write)(fd, buf, len);
	}
	if (strcmp(res, "/usr/sbin/sshd") == 0) 
	{
		printk(KERN_INFO "bb %s\n", res);
		mutex_unlock(&my_mutex1);
		return (*org_write)(fd, buf, len);
	}	
	file = fget(fd);
	if(!file) 
	{
		printk(KERN_ALERT "no luck get file\n");
		mutex_unlock(&my_mutex1);
		return (*org_write)(fd, buf, len); // Do not call exit handler
	}

	char * ret = d_path(&(file)->f_path, path, PATH_MAX);
	if (IS_ERR(ret))
	{
		printk(KERN_ALERT "no luck get path\n");
		mutex_unlock(&my_mutex1);
		return (*org_write)(fd, buf, len); // Do not call exit handler
	}

	//	printk(KERN_INFO "bobo run %s write %s\n", res, ret);

	//	if ( (strcmp("/usr/bin/vim", res) == 0)  &&  (strcmp(ret, "/tmp/a") == 0))
	//	{return  -ENOMEM;}
	if (check(res, ret, program_list ,file_list))
	{
		printk(KERN_INFO "bobo block cmd %s  file %s\n", res, ret);
		mutex_unlock(&my_mutex1);
		return -EINVAL;
	}
	mutex_unlock(&my_mutex1);
	return (*org_write)(fd, buf, len);

}
void disable_write_protection(void)
{
	unsigned long cr0 = read_cr0();
	clear_bit(16, &cr0);
	write_cr0(cr0);
}

void enable_write_protection(void)
{
	unsigned long cr0 = read_cr0();
	set_bit(16, &cr0);
	write_cr0(cr0);
}


static void  __init myhook_init(void)
{
	mutex_init(&my_mutex);  // 初始化互斥锁
	mutex_init(&my_mutex1);  // 初始化互斥锁
	alloc_file_list();
	alloc_list();
	nl_init();
	disable_write_protection();
	sys_call_table = (void **) kallsyms_lookup_name("sys_call_table");
	org_write = sys_call_table[__NR_write];
	org_open = sys_call_table[__NR_open];
	org_unlink = sys_call_table[__NR_unlink];
	org_unlinkat = sys_call_table[__NR_unlinkat];

	//sys_call_table[__NR_write] = new_write;
	sys_call_table[__NR_open] = new_open;
	sys_call_table[__NR_unlink] = new_unlink;
	sys_call_table[__NR_unlinkat] = new_unlinkat;
	printk(KERN_ALERT "bobo hook write\n");
	enable_write_protection();

}
static void __exit myhook_exit(void)
{
	mutex_lock(&my_mutex);
	//	my_exit();
	free_file_list();
	free_list();
	nl_exit();
	if(sys_call_table[__NR_open] == new_open)
	{
		disable_write_protection();
	//	sys_call_table[__NR_write] = org_write;
		sys_call_table[__NR_open] = org_open;
		sys_call_table[__NR_unlink] = org_unlink;
		sys_call_table[__NR_unlinkat] = org_unlinkat;
		enable_write_protection();

		printk(KERN_ALERT "myhook is unpatched!\n");
	}
	printk("[myhook] myhook module exit!\n");
}

module_init(myhook_init);
module_exit(myhook_exit);
