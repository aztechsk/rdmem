// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * rdmem
 *
 * Copyright (c) 2024 Jan Rusnak <jan@rusnak.sk>
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <asm/io.h>
#include "logmsg.h"
#include "rdmem_ioctl.h"

MODULE_AUTHOR("Jan Rusnak <jan@rusnak.sk>");
MODULE_DESCRIPTION("rdmem reads physical memory region");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

struct mem_remap {
	unsigned long phys_addr;
	unsigned long size;
	void __iomem *kv_addr;
	enum rdmem_read_align read_align;
	struct mutex mtx;
};

static int __init rdmem_init(void);
static int open_rdmem(struct inode *inode, struct file *file);
static ssize_t read_rdmem(struct file *file, char __user *buf, size_t count, loff_t *pos);
static ssize_t write_rdmem(struct file *file, const char __user *buf, size_t count, loff_t *pos);
static int close_rdmem(struct inode *inode, struct file *file);
static long rdmem_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static void __exit rdmem_exit(void);

static struct mem_remap mem_remap;

static const struct file_operations file_operations = {
	.owner = THIS_MODULE,
	.open = open_rdmem,
	.read = read_rdmem,
	.write = write_rdmem,
	.release = close_rdmem,
	.llseek = no_llseek,
	.unlocked_ioctl = rdmem_ioctl
};

static struct miscdevice miscdevice = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "rdmem",
	.mode = 0666,
	.fops = &file_operations
};

/**
 * rdmem_init
 */
static int __init rdmem_init(void)
{
	int ret;

	ret = misc_register(&miscdevice);
	if (ret) {
		logerr("Failed to register misc device\n");
		return ret;
	}
	mutex_init(&mem_remap.mtx);
	loginfo("Hello. Device node file /dev/%s 10,%d\n", miscdevice.name, miscdevice.minor);
	return 0;
}

/**
 * open_rdmem
 */
static int open_rdmem(struct inode *inode, struct file *file)
{
	return nonseekable_open(inode, file);
}

/**
 * read_rdmem
 */
static ssize_t read_rdmem(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	char *kbuf;
	ssize_t ret;
	int cnt;

	if (count % 4 || !count)
		return -EINVAL;
	mutex_lock(&mem_remap.mtx);
	if (!mem_remap.kv_addr) {
		mutex_unlock(&mem_remap.mtx);
		return -EINVAL;
	}
	if (count > mem_remap.size)
		ret = mem_remap.size;
	else
		ret = count;
	kbuf = kzalloc(ret, GFP_KERNEL);
	if (unlikely(!kbuf)) {
		mutex_unlock(&mem_remap.mtx);
		return -ENOMEM;
	}
	if (mem_remap.read_align == RDMEM_READ_ALIGN_32)
		cnt = ret / 4;
	else if (mem_remap.read_align == RDMEM_READ_ALIGN_16)
		cnt = ret / 2;
	else
		cnt = ret;
	for (int i = 0; i < cnt; i++) {
		if (mem_remap.read_align == RDMEM_READ_ALIGN_32)
			*((u32 *) kbuf + i) = ioread32((u32 *) mem_remap.kv_addr + i);
		else if (mem_remap.read_align == RDMEM_READ_ALIGN_16)
			*((u16 *) kbuf + i) = ioread16((u16 *) mem_remap.kv_addr + i);
		else
			*(kbuf + i) = ioread8((u8 *) mem_remap.kv_addr + i);
	}
	if (copy_to_user(buf, kbuf, ret)) {
		logerr("copy_to_user() fail\n");
		ret = -EFAULT;
	}
	mutex_unlock(&mem_remap.mtx);
	kfree(kbuf);
	return ret;
}

/**
 * write_rdmem
 */
static ssize_t write_rdmem(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	return -EINVAL;
}

/**
 * close_rdmem
 */
static int close_rdmem(struct inode *inode, struct file *file)
{
	mutex_lock(&mem_remap.mtx);
	if (mem_remap.kv_addr) {
		iounmap(mem_remap.kv_addr);
		release_mem_region(mem_remap.phys_addr, mem_remap.size);
		mem_remap.kv_addr = NULL;
	}
	mutex_unlock(&mem_remap.mtx);
	return 0;
}

/**
 * rdmem_ioctl
 */
static long rdmem_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct rdmem_ioctl_addr addr;

	if (_IOC_TYPE(cmd) != IOCTL_RDMEM_MAGIC) {
		logerr("Ioctl fail, bad magic\n");
		return -ENOTTY;
	}
	if (_IOC_NR(cmd) > IOCTL_RDMEM_MAXIOCTL) {
		logerr("Ioctl fail, bad command\n");
		return -ENOTTY;
	}
	switch (cmd) {
	case IOCTL_RDMEM_MAP_MEMORY:
		if (copy_from_user(&addr, (struct rdmem_ioctl_addr *) arg, sizeof(struct rdmem_ioctl_addr))) {
			logerr("Ioctl fail, copy_from_user() error\n");
			return -EFAULT;
		}
		if (addr.addr % 4)
			return -EINVAL;
		if (addr.size % 4 || !addr.size)
			return -EINVAL;
		switch (addr.read_align) {
		case RDMEM_READ_ALIGN_8:
		case RDMEM_READ_ALIGN_16:
		case RDMEM_READ_ALIGN_32:
			break;
		default:
			return -EINVAL;
		}
		mutex_lock(&mem_remap.mtx);
		if (mem_remap.kv_addr) {
			iounmap(mem_remap.kv_addr);
			release_mem_region(mem_remap.phys_addr, mem_remap.size);
			mem_remap.kv_addr = NULL;
		}
		{
			struct resource *mem_reg;

			mem_reg = request_mem_region(addr.addr, addr.size, miscdevice.name);
			if (mem_reg == NULL) {
				logerr("Ioctl fail, request_mem_region() error\n");
				goto err;
			}
			mem_remap.kv_addr = ioremap(addr.addr, addr.size);
			if (mem_remap.kv_addr == NULL) {
				logerr("Ioctl fail, ioremap() error\n");
				goto err;
			}
			mem_remap.phys_addr = addr.addr;
			mem_remap.size = addr.size;
			mem_remap.read_align = addr.read_align;
			mutex_unlock(&mem_remap.mtx);
			return 0;
err:
			if (mem_reg)
				release_mem_region(addr.addr, addr.size);
			mutex_unlock(&mem_remap.mtx);
			return -ENOMEM;
		}
		break;
	default:
		return -ENOTTY;
	}
}

/**
 * rdmem_exit
 */
static void __exit rdmem_exit(void)
{
	misc_deregister(&miscdevice);
	mutex_destroy(&mem_remap.mtx);
	loginfo("Bye\n");
}

module_init(rdmem_init);
module_exit(rdmem_exit);
