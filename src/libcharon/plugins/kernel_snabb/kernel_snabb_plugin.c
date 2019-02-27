/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */


#include "kernel_snabb_plugin.h"

#include "kernel_snabb_ipsec.h"

#include <sa/task_manager.h>

typedef struct private_kernel_snabb_plugin_t private_kernel_snabb_plugin_t;

/**
 * private data of kernel snabb plugin
 */
struct private_kernel_snabb_plugin_t {
	/**
	 * implements plugin interface
	 */
	kernel_snabb_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_kernel_snabb_plugin_t *this)
{
	return "kernel-snabb";
}

METHOD(plugin_t, get_features, int,
	private_kernel_snabb_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK(kernel_ipsec_register, kernel_snabb_ipsec_create),
			PLUGIN_PROVIDE(CUSTOM, "kernel-ipsec"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, reload, bool,
	private_kernel_snabb_plugin_t *this)
{
	return TRUE;
}

METHOD(plugin_t, destroy, void,
	private_kernel_snabb_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *kernel_snabb_plugin_create()
{
	private_kernel_snabb_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.reload = _reload,
				.destroy = _destroy,
			},
		},
	);

	reload(this);

	return &this->public.plugin;
}
