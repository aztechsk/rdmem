/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * rdmem_ioctl
 *
 * Copyright (c) 2024 Jan Rusnak <jan@rusnak.sk>
 */

#ifndef RDMEM_IOCTL_H
#define RDMEM_IOCTL_H

enum rdmem_read_align {
	RDMEM_READ_ALIGN_8,
	RDMEM_READ_ALIGN_16,
	RDMEM_READ_ALIGN_32,
	RDMEM_READ_ALIGN_SZ
};

struct rdmem_ioctl_addr {
	unsigned long addr;
	unsigned long size;
	enum rdmem_read_align read_align;
};

#define IOCTL_RDMEM_MAGIC 0xB1
#define	IOCTL_RDMEM_MAXIOCTL 1

#define IOCTL_RDMEM_MAP_MEMORY _IOW(IOCTL_RDMEM_MAGIC, 0, struct rdmem_ioctl_addr)

#endif
