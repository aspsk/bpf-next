/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NETDEVSIM_HELPERS_H
#define NETDEVSIM_HELPERS_H

#include <net/if.h>
#include <stddef.h>

int netdevsim_create(char *ifname_retp, size_t ifname_sz);
void netdevsim_destroy(unsigned int id);

#endif /* NETDEVSIM_HELPERS_H */
