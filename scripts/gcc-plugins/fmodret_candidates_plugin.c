// SPDX-License-Identifier: GPL-2.0-only
/* GCC plugin infrastructure for collecting fmod_ret candidate metadata. */

#include "gcc-common.h"

__visible int plugin_is_GPL_compatible;

static bool disable;

static struct plugin_info fmodret_candidates_plugin_info = {
	.version = PLUGIN_VERSION,
	.help = "disable\tdo not emit fmod_ret candidates\n",
};

static unsigned int fmodret_candidates_execute(void)
{
	return 0;
}

#define PASS_NAME fmodret_candidates
#define NO_GATE
#define PROPERTIES_REQUIRED (PROP_gimple_leh | PROP_cfg | PROP_ssa)
#define TODO_FLAGS_FINISH 0
#include "gcc-generate-gimple-pass.h"

__visible int plugin_init(struct plugin_name_args *plugin_info,
			  struct plugin_gcc_version *version)
{
	const char *plugin_name = plugin_info->base_name;
	int i;

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}
	for (i = 0; i < plugin_info->argc; i++) {
		if (!strcmp(plugin_info->argv[i].key, "disable"))
			disable = true;
		else {
			error(G_("unknown option '-fplugin-arg-%s-%s'"),
			      plugin_name, plugin_info->argv[i].key);
			return 1;
		}
	}
	if (disable)
		return 0;

	PASS_INFO(fmodret_candidates, "optimized", 1,
		  PASS_POS_INSERT_BEFORE);
	register_callback(plugin_name, PLUGIN_INFO, NULL,
			  &fmodret_candidates_plugin_info);
	register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL,
			  &fmodret_candidates_pass_info);
	return 0;
}
