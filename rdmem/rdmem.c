/*
 * rdmem.c
 *
 * Copyright (c) 2024 Jan Rusnak <jan@rusnak.sk>
 */

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdbool.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <signal.h>
#include "../lkm/rdmem_ioctl.h"

static struct rdmem_ioctl_addr ioctl_addr;
static const char *const dev_path = "/dev/rdmem";
static char *mem_buf;
static int dev_file = -1;
static volatile bool ctrlc;

static void logmsg(int prio, ...);
static void dump_hex(const char buf[static 4], int size);
static void on_exit_clean(int code, void *p);
static void ctrlc_handler(int s);
static void parse_options(int argc, char **argv);

/**
 * main
 */
int main(int argc, char **argv)
{
	signal(SIGINT, ctrlc_handler);
	if (0 != on_exit(on_exit_clean, NULL)) {
		logmsg(LOG_ERR, "Register on_exit_clean() fail.\n");
		exit(EXIT_FAILURE);
	}
	if (setvbuf(stdout, NULL, _IOLBF, 0)) {
		logmsg(LOG_ERR, "setvbuf() fail.\n");
		exit(EXIT_FAILURE);
	}
	if (setvbuf(stderr, NULL, _IOLBF, 0)) {
		logmsg(LOG_ERR, "setvbuf() fail.\n");
		exit(EXIT_FAILURE);
	}
	parse_options(argc, argv);
	dev_file = open(dev_path, O_RDONLY);
	if (dev_file == -1) {
		logmsg(LOG_ERR, "Open file \"%s\" fail. %s.\n", dev_path, strerror(errno));
		exit(EXIT_FAILURE);
	}
	mem_buf = calloc(ioctl_addr.size, 1);
	if (!mem_buf) {
		logmsg(LOG_ERR, "calloc() fail.\n");
		exit(EXIT_FAILURE);
	}
	if (ioctl(dev_file, IOCTL_RDMEM_MAP_MEMORY, &ioctl_addr) < 0) {
		logmsg(LOG_ERR, "Ioctl on \"%s\" fail. %s.\n", dev_path, strerror(errno));
		exit(EXIT_FAILURE);
	}
	int cnt = 0;
	while (true) {
		if (!(cnt % 25)) {
			int rcnt = read(dev_file, mem_buf, ioctl_addr.size);
			if (rcnt == -1) {
				logmsg(LOG_ERR, "Read on \"%s\" fail. %s.\n", dev_path, strerror(errno));
				exit(EXIT_FAILURE);
			}
			if ((unsigned long) rcnt != ioctl_addr.size) {
				logmsg(LOG_ERR, "Read on \"%s\" fail (rcnt != ioctl_addr.size).\n", dev_path);
				exit(EXIT_FAILURE);
			}			
			dump_hex(mem_buf, ioctl_addr.size);
		}
		cnt++;
		usleep(200000);
		if (ctrlc) {
			printf("\n");
			break;
		}
	}
	exit(EXIT_SUCCESS);
}

/**
 * dump_hex
 */
static void dump_hex(const char buf[static 4], int size) 
{
	for (int i = 0, m = 0; i < size; ++i, ++m) {
		printf("%02X", buf[i]);
		if (m % 2) {
			if (m == 15) {
				if (i != size - 1) {
					printf("\n");
				}
				m = -1;
			} else {
				if (m == 3 || m == 7 || m == 11) {
					printf(" ");
				} else {
					printf(".");
				}
			}
		}
	}
	printf("\n---------\n");
}

/**
 * on_exit_clean
 */
static void on_exit_clean(int __attribute__((unused)) code, void __attribute__((unused)) *p)
{
	if (mem_buf) {
		free(mem_buf);
	}
	if (dev_file != -1) {
		close(dev_file);
	}
}

/**
 * ctrlc_handler
 */
static void ctrlc_handler(int __attribute__((unused)) s)
{
	ctrlc = true;
}

/**
 * parse_options
 */
static void parse_options(int argc, char **argv)
{
	int c;
	const char *a = NULL, *s = NULL, *b = NULL;

	opterr = 0;
	while ((c = getopt(argc, argv, ":a:s:b:")) != -1) {
		switch (c) {
		case 'a' :
			a = optarg;
			break;
		case 's' :
			s = optarg;
			break;
		case 'b' :
			b = optarg;
			break;
		case '?' :
			if (isprint(optopt)) {
				logmsg(LOG_ERR, "Unknown option -%c.\n", optopt);
			} else {
				logmsg(LOG_ERR, "Unknown option character \\x%x.\n");
			}
			exit(EXIT_FAILURE);
		case ':' :
			logmsg(LOG_ERR, "Option -%c requires argument.\n", optopt);
			exit(EXIT_FAILURE);
		}
	}
	if (!a) {
		logmsg(LOG_ERR, "Option -a required.\n");
		exit(EXIT_FAILURE);
	}
	if (!s) {
		logmsg(LOG_ERR, "Option -s required.\n");
		exit(EXIT_FAILURE);
	}
	if (!b) {
		logmsg(LOG_ERR, "Option -b required.\n");
		exit(EXIT_FAILURE);
	}
	errno = 0;
	char *tailptr = NULL;
	ioctl_addr.addr = strtoul(a, &tailptr, 16);
	if (errno || *tailptr != '\0' || ioctl_addr.addr % 4) {
		logmsg(LOG_ERR, "Option -a bad format.\n");
		exit(EXIT_FAILURE);
	}
	errno = 0;
	tailptr = NULL;
	ioctl_addr.size = strtoul(s, &tailptr, 0);
	if (errno || *tailptr != '\0' || ioctl_addr.size % 4 || !ioctl_addr.size) {
		logmsg(LOG_ERR, "Option -s bad format.\n");
		exit(EXIT_FAILURE);
	}
	errno = 0;
	tailptr = NULL;
	int align = strtol(b, &tailptr, 0);
	if (errno || *tailptr != '\0') {
		logmsg(LOG_ERR, "Option -b bad format.\n");
		exit(EXIT_FAILURE);
	}
	const char *bstr;
	if (align == 8) {
		bstr = "B8";
		ioctl_addr.read_align = RDMEM_READ_ALIGN_8;
	} else if (align == 16) {
		bstr = "B16";
		ioctl_addr.read_align = RDMEM_READ_ALIGN_16;
	} else if (align == 32) {
		bstr = "B32";
		ioctl_addr.read_align = RDMEM_READ_ALIGN_32;
	} else {
		logmsg(LOG_ERR, "Option -b bad format.\n");
		exit(EXIT_FAILURE);
	}
	logmsg(LOG_INFO, "Options: address=0x%016lX size=%lu read=%s.\n", ioctl_addr.addr, ioctl_addr.size, bstr);
}

/**
 * logmsg
 */
static void logmsg(int prio, ...)
{
	va_list ap;
	FILE *file;
	const char *fmt;

	file = (prio <= LOG_ERR) ? stderr : stdout;
	va_start(ap, prio);
	fmt = va_arg(ap, const char *);
	if (prio <= LOG_ERR) {
		fprintf(stderr, "Error: ");
	}
	vfprintf(file, fmt, ap);
	va_end(ap);
}
