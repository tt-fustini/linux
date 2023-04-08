/*
 * DO NOT MERGE
 * Simple test driver to set thread.sqoscfg for the current task
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <asm/qos.h>

static struct kobject *thread_qoscfg_kobj;

/* Sysfs file read function */
static ssize_t thread_qoscfg_value_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct task_struct *task = current;
	u32 thread_qoscfg;

	thread_qoscfg = READ_ONCE(task->thread.sqoscfg);
	trace_printk("DEBUG %s(): task->pid=%d thread_qoscfg=%d", __func__, task->pid, thread_qoscfg);

	return sprintf(buf, "%d\n", thread_qoscfg);
}

/* Sysfs file write function */
static ssize_t thread_qoscfg_value_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct task_struct *task = current;
	u32 thread_qoscfg;
	u32 old_thread_qoscfg;
	int value;

	if (kstrtoint(buf, 10, &value) < 0)
		return -EINVAL;
	trace_printk("DEBUG %s(): task->pid=%d value=%d", __func__, task->pid, value);

	old_thread_qoscfg = READ_ONCE(task->thread.sqoscfg);
	trace_printk("DEBUG %s(): old_thread.sqoscfg=0x%x", __func__, old_thread_qoscfg);

	trace_printk("DEBUG %s(): write value to thread.sqoscfg=0x%x for pid=%d", __func__, value, task->pid);
	WRITE_ONCE(task->thread.sqoscfg, value);

	thread_qoscfg = READ_ONCE(task->thread.sqoscfg);
	trace_printk("DEBUG %s(): read thread.sqoscfg=%d for pid=%d", __func__, thread_qoscfg, task->pid);

	return count;
}

/* Sysfs attributes */
static struct kobj_attribute thread_qoscfg_value_attr = __ATTR(thread_qoscfg_value, 0660, thread_qoscfg_value_show, thread_qoscfg_value_store);

/* Initialize the module */
static int __init thread_qoscfg_init(void)
{
	int error = 0;

	/* Create a kobject */
	thread_qoscfg_kobj = kobject_create_and_add("thread_qoscfg", kernel_kobj);
	if (!thread_qoscfg_kobj)
		return -ENOMEM;

	/* Create sysfs file attributes */
	error = sysfs_create_file(thread_qoscfg_kobj, &thread_qoscfg_value_attr.attr);
	if (error) {
		kobject_put(thread_qoscfg_kobj);
		return error;
	}

	return 0;
}

/* Cleanup the module */
static void __exit thread_qoscfg_exit(void)
{
	/* Remove sysfs file attributes */
	sysfs_remove_file(thread_qoscfg_kobj, &thread_qoscfg_value_attr.attr);

	/* Remove the kobject */
	kobject_put(thread_qoscfg_kobj);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Drew Fustini");
MODULE_DESCRIPTION("Test sysfs module for RISC-V Ssqosid");
module_init(thread_qoscfg_init);
module_exit(thread_qoscfg_exit);

