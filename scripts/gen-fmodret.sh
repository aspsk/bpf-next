#!/bin/sh -e
# SPDX-License-Identifier: GPL-2.0
#
# This script is a wrapper which runs the $GEN_FMODRET_IDS tool (defaults to
# tools/bpf/gen_fmodret_ids/gen_fmodret_ids) and thus builds up the fmod-ret
# BTF ID data for the provided ELF file, be it the vmlinux or a module. For
# vmlinux a new relocatable object is produced, for modules the section
# is embedded directly into the input ELF file.

case "${KBUILD_VERBOSE}" in
*1*)
	set -x
	;;
esac

${GEN_FMODRET_IDS} "$@"
