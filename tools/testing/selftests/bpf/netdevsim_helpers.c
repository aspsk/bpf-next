// SPDX-License-Identifier: GPL-2.0

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include "netdevsim_helpers.h"

static int echo(const char *path, const char *fmt, ...)
{
	char buf[64];
	va_list ap;
	int fd, len, err = 0;

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -errno;
	if (write(fd, buf, len) != len)
		err = -errno;
	close(fd);

	return err;
}

void netdevsim_destroy(unsigned int id)
{
	echo("/sys/bus/netdevsim/del_device", "%u", id);
}

static int new_device(void)
{
	unsigned int id;
	int err;

	for (id = 0; id < 1024; id++) {
		err = echo("/sys/bus/netdevsim/new_device", "%u", id);
		if (!err)
			return id;
		if (err != -ENOSPC)
			return err;
	}

	return -ENOSPC;
}

static int get_device_name(unsigned int id, char *ifname, size_t ifname_sz)
{
	char path[128];
	struct dirent *e;
	int err = -ENOENT;
	DIR *d;

	snprintf(path, sizeof(path), "/sys/bus/netdevsim/devices/netdevsim%u/net", id);
	d = opendir(path);
	if (!d)
		return -errno;

	while ((e = readdir(d))) {
		if (e->d_name[0] == '.')
			continue;
		snprintf(ifname, ifname_sz, "%s", e->d_name);
		err = 0;
		break;
	}
	closedir(d);

	return err;
}

int netdevsim_create(char *ifname, size_t ifname_sz)
{
	int id, err;

	id = new_device();
	if (id < 0)
		return id;

	err = get_device_name(id, ifname, ifname_sz);
	if (err) {
		netdevsim_destroy(id);
		return err;
	}

	return id;
}
