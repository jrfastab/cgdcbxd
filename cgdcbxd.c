/*
 * Copyright Intel Corporation. 2012
 *
 * Authors:	John Fastabend <john.r.fastabend@lintel.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 */

#include <libcgroup.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <libmnl/libmnl.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <linux/dcbnl.h>
#include <sys/queue.h>
#include <signal.h>
#include <sys/select.h>
#include <syslog.h>
#include <sys/file.h>
#include <unistd.h>
#include <time.h>

#define UNUSED __attribute__((__unused__))

#define PID_FILE "/var/run/cgdcbxd.pid"
#define NET_PRIO "net_prio"
#define IFPRIOMAP "net_prio.ifpriomap"

struct cgdcbx_virt {
	char *ifname;
	int ifindex;
	__u32 iflink;
	LIST_ENTRY(cgdcbx_virt) entry;
};

struct cgdcbx_entry {
	struct dcb_app app;
	bool active;
	LIST_ENTRY(cgdcbx_entry) entry;
};

struct cgdcbx_iface {
	char *ifname;
	int mode;
	int ifindex;
	int dflt_priority;
	LIST_HEAD(cgdcbx_apps, cgdcbx_entry) apps;
	LIST_HEAD(cgdcbx_slaves, cgdcbx_virt) virt;
	LIST_ENTRY(cgdcbx_iface) entry;
};

LIST_HEAD(cgdcbx_iface_head, cgdcbx_iface) iface_list;

static void usage(const char *program_name)
{
	fprintf(stderr,
		"\n"
		"Usage: %s [-hn]"
		"\n"
		"options:\n"
		"   -h  show this usage\n"
		"   -n  don't fork daemon\n",
		program_name);
}

static int dcb_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = (const struct nlattr **)data;
	int type = mnl_attr_get_type(attr);
	int ret = 0;

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, DCB_CMD_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case DCB_ATTR_IFNAME:
		ret = mnl_attr_validate(attr, MNL_TYPE_STRING);
		break;
	case DCB_ATTR_APP:
		ret = mnl_attr_validate(attr, MNL_TYPE_NESTED);
		break;
	case DCB_CMD_GDCBX:
		ret = mnl_attr_validate(attr, MNL_TYPE_U8);
		break;
	}

	if (ret < 0) {
		perror("mnl_attr_validate");
		return MNL_CB_ERROR;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int parse_attr_ieee(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, DCB_ATTR_IEEE_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case DCB_ATTR_IEEE_APP_TABLE:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
			perror("mnl_attr_validate: DCB_ATTR_IEEE_APP_TABLE");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int parse_attr_cee(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, DCB_ATTR_CEE_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case DCB_ATTR_CEE_APP_TABLE:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
			perror("mnl_attr_validate: DCB_ATTR_CEE_TABLE");
			return MNL_CB_ERROR;
		}

		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static struct cgdcbx_entry *__cgdcbx_lookup_app(struct cgdcbx_iface *iface,
						struct dcb_app *app)
{
	struct cgdcbx_entry *np;

	LIST_FOREACH(np, &iface->apps, entry) {
		if (np->app.selector == app->selector &&
		    np->app.protocol == app->protocol)
			return np;
	}

	return NULL;
}

static struct cgdcbx_entry *cgdcbx_lookup_app(struct cgdcbx_iface *iface,
					      struct dcb_app *app)
{
	struct cgdcbx_entry *entry = __cgdcbx_lookup_app(iface, app);

	if (entry) {
		entry->app.priority = app->priority;
		entry->active = true;
	} else {
		entry = malloc(sizeof(*entry));
		if (!entry)
			return NULL;

		memcpy(&entry->app, app, sizeof(entry->app));
		entry->active = true;
		LIST_INSERT_HEAD(&iface->apps, entry, entry);
	}

	return entry;
}

static int cgdcbx_del_cgroup(struct cgroup *cg)
{
	int err = cgroup_delete_cgroup(cg, 1);

	if (err)
		fprintf(stderr, "cgdcbx: libcgroup delete cgroup failed: %s\n",
			cgroup_strerror(err));
	return err;
}

static int link_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = (const struct nlattr **)data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, IFLA_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case IFLA_IFNAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			perror("mnl_attr_validate IFLA_IFNAME");
			return MNL_CB_ERROR;
		}
		break;
	case IFLA_LINK:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate IFLA_LINK");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

struct cgdcbx_link_data {
	struct cgdcbx_iface *iface;
	struct cgdcbx_virt *virt;
	int nlmsg_type;
	unsigned ifi_flags;
};

static int cgdcbx_link_cb(const struct nlmsghdr *nlh, void *data)
{
	struct cgdcbx_iface *iface = NULL;
	struct cgdcbx_virt *virt = NULL;
	struct cgdcbx_link_data *cgdcbx_data = data;
	const struct nlattr *tb[IFLA_MAX+1] = {};
	struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*ifm), link_attr_cb, tb);

	/* Require IFLA_IFNAME attribute to build priomap string */
	if (!tb[IFLA_IFNAME])
		goto out;

	/* Add priomap string to cgroup */
	if (tb[IFLA_LINK]) {
		struct cgdcbx_virt *v;
		__u32 iflink = mnl_attr_get_u32(tb[IFLA_LINK]);

		/* Check that device does not already exist */
		LIST_FOREACH(iface, &iface_list, entry) {
			LIST_FOREACH(virt, &iface->virt, entry) {
				if (virt->ifindex == ifm->ifi_index)
					goto out;
			}
		}

		virt = malloc(sizeof(struct cgdcbx_virt));
		if (!virt)
			goto out;

		virt->ifname = strdup(mnl_attr_get_str(tb[IFLA_IFNAME]));
		virt->ifindex = ifm->ifi_index;
		virt->iflink = iflink;

		/* Devices can be stacked on other virtual devices so we
		 * must search list of virtual devices for a map and add
		 * to virtual device list to propagate priority.
		 */
		LIST_FOREACH(iface, &iface_list, entry) {
			if (iflink == if_nametoindex(iface->ifname)) {
				LIST_INSERT_HEAD(&iface->virt, virt, entry);
				goto out;
			}
			LIST_FOREACH(v, &iface->virt, entry) {
				if (iflink == if_nametoindex(v->ifname)) {
					LIST_INSERT_HEAD(&iface->virt,
							 virt,
							 entry);
					goto out;
				}
			}
		}

		free(virt->ifname);
		free(virt);
	} else {
		/* Check that device does not already exist */
		LIST_FOREACH(iface, &iface_list, entry) {
			if (iface->ifindex == ifm->ifi_index)
				goto out;
		}

		/* If device is not being tracked wait for DCB event */
	}
	iface = NULL;
	virt = NULL;
out:
	if (cgdcbx_data) {
		cgdcbx_data->nlmsg_type = nlh->nlmsg_type;
		cgdcbx_data->iface = iface;
		cgdcbx_data->virt = virt;
		cgdcbx_data->ifi_flags = ifm->ifi_flags;
	}
	return MNL_CB_OK;
}

static void cgdcbx_write_virtmap(struct cgdcbx_virt *virt,
				 char *file, struct cgdcbx_entry *np)
{
	struct cgroup *vcg_app;
	struct cgroup_controller *vcg_ctrl;
	char value[IFNAMSIZ + 3];
	int err;

	vcg_app = cgroup_new_cgroup(file);
	if (!vcg_app) {
		fprintf(stderr,
			"cgdcbx: libcgroup %s cgroup_new_cgroup failed\n",
			file);
		return;
	}

	vcg_ctrl = cgroup_get_controller(vcg_app, NET_PRIO);
	if (!vcg_ctrl) {
		vcg_ctrl = cgroup_add_controller(vcg_app, NET_PRIO);
		if (!vcg_ctrl)
			return;
	}

	err = cgroup_create_cgroup(vcg_app, 1);
	if (err) {
		fprintf(stderr,
			"cgdcbx: libcgroup %s create failed: %s\n",
			file,
			cgroup_strerror(err));
	}

	snprintf(value, sizeof(value), "%s %i", virt->ifname, np->app.priority);

	err = cgroup_add_value_string(vcg_ctrl, IFPRIOMAP, value);
	if (err) {
		fprintf(stderr,
			"cgdcbx: %s: libcgroup %s add value failed: %s\n",
			virt->ifname, file, cgroup_strerror(err));
	}

	err = cgroup_modify_cgroup(vcg_app);
	cgroup_free(&vcg_app);
}

static void cgdcbx_write_ifpriomap(struct cgdcbx_iface *iface, char *file,
				   struct cgdcbx_entry *np)
{
	struct cgroup *cg_app;
	struct cgroup_controller *cg_ctrl;
	int err;

	cg_app = cgroup_new_cgroup(file);
	if (!cg_app) {
		fprintf(stderr,
			"cgdcbx: libcgroup %s cgroup_new_cgroup failed\n",
			file);
		return;
	}

	cg_ctrl = cgroup_get_controller(cg_app, NET_PRIO);
	if (!cg_ctrl) {
		cg_ctrl = cgroup_add_controller(cg_app, NET_PRIO);
		if (!cg_ctrl) {
			fprintf(stderr,
				"cgdcbx: libcgroup %s get & add failed\n",
				file);
			goto err;
		}
	}

	if (!np->active) {
		struct cgdcbx_iface *itr;
		struct cgdcbx_entry *entry = NULL;
		struct dcb_app app = np->app;

		entry = __cgdcbx_lookup_app(iface, &np->app);
		if (entry) {
			LIST_REMOVE(entry, entry);
			free(entry);
		} else {
			fprintf(stderr, "cgdcbx: request delete entry that does not exist\n");
		}

		LIST_FOREACH(itr, &iface_list, entry) {
			entry = __cgdcbx_lookup_app(itr, &app);

			if (entry)
				break;
		}
		/* Only remove cgroup if its not in use */
		if (!entry)
			err = cgdcbx_del_cgroup(cg_app);
	} else {
		char value[IFNAMSIZ + 3];
		struct cgdcbx_virt *virt;

		err = cgroup_create_cgroup(cg_app, 1);
		if (err) {
			fprintf(stderr,
				"cgdcbx: libcgroup %s create failed: %s\n",
				file,
				cgroup_strerror(err));
			goto err;
		}

		snprintf(value, sizeof(value), "%s %i",
			 iface->ifname, np->app.priority);
		err = cgroup_add_value_string(cg_ctrl, IFPRIOMAP, value);
		if (err) {
			fprintf(stderr,
				"cgdcbx: %s: libcgroup %s add value failed: %s\n",
				iface->ifname,
				file,
				cgroup_strerror(err));
			goto err;
		}

		/* Update any stacked devices as well */
		virt = LIST_FIRST(&iface->virt);
		while (virt) {
			cgdcbx_write_virtmap(virt, file, np);
			virt = LIST_NEXT(virt, entry);
		}

		err = cgroup_modify_cgroup(cg_app);
		if (err) {
			fprintf(stderr,
				"cgdcbx: libcgroup modify \"%s %s\" cgroup failed(%i): %s\n",
				value,
				file,
				err,
				cgroup_strerror(err));
			goto err;
		}
	}
err:
	cgroup_free(&cg_app);
}

static void cgdcbxd_update_default_iface_prio(struct cgdcbx_iface *iface)
{
	char child_name[FILENAME_MAX] = "";
	void *handle;
	struct cgroup_file_info info;
	int ret, level, group_len;
	struct cgdcbx_entry entry;

	/* Initialize dummy default priority entry */
	entry.app.selector = 1;
	entry.app.protocol = 0;
	entry.app.priority = iface->dflt_priority;
	entry.active = 1;

	ret = cgroup_walk_tree_begin(NET_PRIO, "/", 0, &handle, &info, &level);
	if (ret)
		return;

	ret = cgroup_walk_tree_set_flags(&handle, CGROUP_WALK_TYPE_POST_DIR);
	if (ret) {
		cgroup_walk_tree_end(&handle);
		return;
	}

	cgdcbx_write_ifpriomap(iface, "/", &entry);

	group_len = strlen(info.full_path);

	/*
	 * Skip the root group, it will be handled explicitly at the end.
	 */
	ret = cgroup_walk_tree_next(0, &handle, &info, level);

	while (ret == 0) {
		if (info.type == CGROUP_FILE_TYPE_DIR && info.depth > 0) {
			struct cgdcbx_entry *np;
			int selector = 0, protocol = 0;

			snprintf(child_name, sizeof(child_name), "%s",
				 info.full_path + group_len);
			sscanf(info.full_path + group_len,
			      "cgdcb-%i", &selector);

			if (selector == 1)
				sscanf(info.full_path + group_len,
				      "cgdcb-%i-%4x", &selector, &protocol);
			else
				sscanf(info.full_path + group_len,
				       "cgdcb-%i-%i", &selector, &protocol);


			LIST_FOREACH(np, &iface->apps, entry) {
				if (np->app.selector == selector &&
				    np->app.protocol == protocol)
					break;
			}

			if (!np)
				cgdcbx_write_ifpriomap(iface,
						       child_name, &entry);
		}
		ret = cgroup_walk_tree_next(0, &handle, &info, level);
	}
	cgroup_walk_tree_end(&handle);
	return;
}

static void cgdcbx_modify_cgroup(struct cgdcbx_iface *iface,
				 struct cgdcbx_entry *np)
{
	char file[19];

	/* selector == 1 and protocol == 0 is a special case which
	 * indicates the default priority should be set. All other
	 * cases use the selector-protocol control group syntax.
	 */
	if ((iface->mode == DCB_CAP_DCBX_VER_IEEE) &&
	    np->app.selector == 1 &&
	    np->app.protocol == 0) {
		snprintf(file, sizeof(file), "/");
		iface->dflt_priority = np->app.priority;
	} else if (np->app.selector == 1) {
		snprintf(file, sizeof(file), "cgdcb-%i-%04x",
			 np->app.selector,
			 np->app.protocol);
	} else {
		snprintf(file, sizeof(file), "cgdcb-%i-%i",
			 np->app.selector,
			 np->app.protocol);
	}

	cgdcbx_write_ifpriomap(iface, file, np);
}

static void cgdcbx_update_iface_cg(struct cgdcbx_iface *iface)
{
	struct cgdcbx_entry *entry;

	entry = LIST_FIRST(&iface->apps);
	while (entry) {
		struct cgdcbx_entry *np = entry;

		entry = LIST_NEXT(entry, entry);
		cgdcbx_modify_cgroup(iface, np);
	}

	return;
}

static void cgdcbx_update_iface_cg_all(void)
{
	struct cgdcbx_iface *iface;

	LIST_FOREACH(iface, &iface_list, entry) {
		cgdcbx_update_iface_cg(iface);
	}
#ifdef HAVE_CGROUP_CHANGE_ALL_CGROUPS
	cgroup_change_all_cgroups();
#endif
}

static void cgdcbx_populate_virtual_devs(void)
{
	static struct mnl_socket *nl;
	struct nlmsghdr *nlh;
	struct rtgenmsg *rt;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	unsigned int portid;
	int ret, groups = 0;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (!nl) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(nl, groups, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}
	portid = mnl_socket_get_portid(nl);

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_GETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = time(NULL);

	rt = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));
	rt->rtgen_family = AF_PACKET;

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("cgdcbx: init_tables, mnl_socket_send");
		return;
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid,
				 cgdcbx_link_cb, NULL);
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}

	mnl_socket_close(nl);
	return;
}

static void cgdcbx_free_apps(struct cgdcbx_iface *iface)
{
	struct cgdcbx_entry *app;

	app = LIST_FIRST(&iface->apps);
	while (app) {
		struct cgdcbx_entry *a = app;

		app = LIST_NEXT(app, entry);
		LIST_REMOVE(a, entry);
		free(a);
	}

}

static void cgdcbx_free_virt(struct cgdcbx_iface *iface)
{
	struct cgdcbx_virt *virt;

	virt = LIST_FIRST(&iface->virt);
	while (virt) {
		struct cgdcbx_virt *v = virt;

		virt = LIST_NEXT(virt, entry);
		LIST_REMOVE(v, entry);
		free(v->ifname);
		free(v);
	}
}

static void cgdcbx_free_iface(struct cgdcbx_iface *iface,
			      struct cgdcbx_virt *virt)
{
	if (!virt) {
		LIST_REMOVE(iface, entry);
		cgdcbx_free_apps(iface);
		cgdcbx_free_virt(iface);
		free(iface->ifname);
		free(iface);
	} else {
		LIST_REMOVE(virt, entry);
		free(virt->ifname);
		free(virt);
	}
}

static void cgdcbx_int_signal()
{
	struct cgdcbx_iface *entry;

	entry = LIST_FIRST(&iface_list);
	while (entry) {
		struct cgdcbx_iface *np = entry;
		struct cgdcbx_entry *app;

		entry = LIST_NEXT(entry, entry);

		LIST_FOREACH(app, &np->apps, entry) {
			app->active = false;
		}

		cgdcbx_update_iface_cg(np);
		cgdcbx_free_iface(np, NULL);
	}

	exit(EXIT_SUCCESS);
}

static void cgdcbx_purge_apps(struct cgdcbx_iface *iface)
{
	struct cgdcbx_entry *app;

	LIST_FOREACH(app, &iface->apps, entry)
		app->active = false;

	iface->dflt_priority = 0;
	cgdcbx_update_iface_cg(iface);
	cgdcbxd_update_default_iface_prio(iface);
}

static void cgdcbx_parse_app_table(struct cgdcbx_iface *iface,
				   struct nlattr *nested)
{
	struct nlattr *pos;
	struct cgdcbx_entry *np;

	LIST_FOREACH(np, &iface->apps, entry) {
		np->active = false;
		np->app.priority = 0;
	}

	iface->dflt_priority = 0;

	mnl_attr_for_each_nested(pos, nested) {
		struct dcb_app *app;
		struct cgdcbx_entry *entry;
		int type = mnl_attr_get_type(pos);

		if (type != DCB_ATTR_IEEE_APP)
			continue;

		app = mnl_attr_get_payload(pos);
		entry = cgdcbx_lookup_app(iface, app);
		if (!entry)
			fprintf(stderr,
				"cgdcbxd %s IEEE entry lookup failed\n",
				iface->ifname);
	}

	cgdcbx_update_iface_cg(iface);
	cgdcbxd_update_default_iface_prio(iface);
#ifdef HAVE_CGROUP_CHANGE_ALL_CGROUPS
	cgroup_change_all_cgroups();
#endif
}

static int parse_attr_cee_nested_app(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, DCB_APP_ATTR_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case DCB_APP_ATTR_IDTYPE:
		if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0) {
			perror("mnl_attr_validate: DCB_APP_ATTR_IDTYPE");
			return MNL_CB_ERROR;
		}
		break;
	case DCB_APP_ATTR_ID:
		if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0) {
			perror("mnl_attr_validate: DCB_APP_ATTR_ID");
			return MNL_CB_ERROR;
		}
		break;
	case DCB_APP_ATTR_PRIORITY:
		if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0) {
			perror("mnl_attr_validate: DCB_APP_ATTR_PRIORITY");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

#define CGDCBX_CEE_APPSEL_ERROR	0xff

static __u8 cee2app_selector(__u8 selector)
{
	__u8 s = CGDCBX_CEE_APPSEL_ERROR;

	/* CEE Application TLV defines two selector types,
	 *   0: Application Protocol ID is L2 Ethertype
	 *   1: Application Protocol ID is Socket Number (TCP/UDP)
	 *
	 * When mapping this back to cgdcbx APP structure which
	 * is using the IEEE definitions, map 0 to the IEEE L2
	 * type (1) and TCP/UDP socket to TCP, UDP, SCTP, or DCCP
	 * socket type (4). Not a perfect match but good enough.
	 */
	switch (selector) {
	case 0:
		s = 1;
		break;
	case 1:
		s = 4;
		break;
	default:
		break;
	}

	return s;
}

static __u16 cee2app_protocol(UNUSED __u8 selector, __u16 protocol)
{
	return protocol;
}

static __u8 cee2app_priority(__u8 priority)
{
	return ffs(priority) - 1;
}

static void cgdcbx_parse_cee_app_table(struct cgdcbx_iface *iface,
				       struct nlattr *nested)
{
	struct nlattr *pos;
	struct cgdcbx_entry *np;

	LIST_FOREACH(np, &iface->apps, entry) {
		np->active = false;
		np->app.priority = 0;
	}

	iface->dflt_priority = 0;

	mnl_attr_for_each_nested(pos, nested) {
		struct dcb_app app;
		struct cgdcbx_entry *entry;
		struct nlattr *tbx[DCB_APP_ATTR_MAX + 1] = {};
		int type = mnl_attr_get_type(pos);
		__u8 selector, priority;
		__u16 protocol;

		if (type != DCB_ATTR_APP)
			continue;

		mnl_attr_parse_nested(pos, parse_attr_cee_nested_app, tbx);
		if (tbx[DCB_APP_ATTR_IDTYPE])
			selector = mnl_attr_get_u8(tbx[DCB_APP_ATTR_IDTYPE]);
		else
			continue;

		if (tbx[DCB_APP_ATTR_ID])
			protocol = mnl_attr_get_u16(tbx[DCB_APP_ATTR_ID]);
		else
			continue;

		if (tbx[DCB_APP_ATTR_PRIORITY])
			priority = mnl_attr_get_u8(tbx[DCB_APP_ATTR_PRIORITY]);
		else
			continue;

		app.selector = cee2app_selector(selector);
		app.protocol = cee2app_protocol(selector, protocol);
		app.priority = cee2app_priority(priority);

		if (app.selector != CGDCBX_CEE_APPSEL_ERROR) {
			entry = cgdcbx_lookup_app(iface, &app);
			if (!entry)
				fprintf(stderr,
					"cgdcbxd %s CEE entry lookup failed\n",
					iface->ifname);
		}
	}

	cgdcbx_update_iface_cg(iface);
	cgdcbxd_update_default_iface_prio(iface);
#ifdef HAVE_CGROUP_CHANGE_ALL_CGROUPS
	cgroup_change_all_cgroups();
#endif
}

static struct cgdcbx_iface *cgdcbx_add_iface(const char *ifname)
{
	struct cgdcbx_iface *entry = calloc(1, sizeof(*entry));

	if (!entry)
		return NULL;

	entry->ifname = strdup(ifname);
	entry->ifindex = if_nametoindex(ifname);
	entry->dflt_priority = 0;

	if (!entry->ifname)
		return NULL;

	LIST_INIT(&entry->apps);
	LIST_INIT(&entry->virt);
	LIST_INSERT_HEAD(&iface_list, entry, entry);

	return entry;
}

static struct cgdcbx_iface *cgdcbx_lookup_iface(const char *ifname)
{
	struct cgdcbx_iface *np;

	LIST_FOREACH(np, &iface_list, entry) {
		if (!strncmp(np->ifname, ifname, IFNAMSIZ))
			return np;
	}

	return cgdcbx_add_iface(ifname);
}

static int cgdcbx_getdcbx_reply(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[IFLA_MAX + 1] = {};
	struct dcbmsg *dcb;
	__u8 bitmask = 0;
	__u8 *mode = data;

	if (nlh->nlmsg_type != RTM_GETDCB)
		return MNL_CB_OK;

	dcb = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*dcb), dcb_attr_cb, tb);
	if (tb[DCB_ATTR_DCBX]) {
		bitmask = mnl_attr_get_u8(tb[DCB_ATTR_DCBX]);
		*mode = bitmask &
			(DCB_CAP_DCBX_VER_CEE | DCB_CAP_DCBX_VER_IEEE);
	}

	return MNL_CB_OK;
}

static int cgdcbx_dcb_cb(const struct nlmsghdr *nlh, UNUSED void *data)
{
	struct nlattr *tb[IFLA_MAX + 1] = {};
	struct dcbmsg *dcb;
	struct cgdcbx_iface *iface;

	dcb = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*dcb), dcb_attr_cb, tb);
	if (tb[DCB_ATTR_IFNAME]) {
		const char *ifname = mnl_attr_get_str(tb[DCB_ATTR_IFNAME]);

		iface = cgdcbx_lookup_iface(ifname);
		if (!iface)
			return MNL_CB_OK;
	} else {
		return MNL_CB_STOP;
	}

	if (tb[DCB_ATTR_IEEE]) {
		struct nlattr *tbx[DCB_ATTR_IEEE_MAX + 1] = {};
		struct nlattr *app_nest;

		if (iface->mode != DCB_CAP_DCBX_VER_IEEE) {
			cgdcbx_purge_apps(iface);
			iface->mode = DCB_CAP_DCBX_VER_IEEE;
		}

		mnl_attr_parse_nested(tb[DCB_ATTR_IEEE], parse_attr_ieee, tbx);
		app_nest = tbx[DCB_ATTR_IEEE_APP_TABLE];
		if (app_nest)
			cgdcbx_parse_app_table(iface, app_nest);
	}

	if (tb[DCB_ATTR_CEE]) {
		struct nlattr *tbx[DCB_ATTR_CEE_MAX + 1] = {};
		struct nlattr *app_nest;

		if (iface->mode != DCB_CAP_DCBX_VER_CEE) {
			cgdcbx_purge_apps(iface);
			iface->mode = DCB_CAP_DCBX_VER_CEE;
		}

		mnl_attr_parse_nested(tb[DCB_ATTR_CEE], parse_attr_cee, tbx);
		app_nest = tbx[DCB_ATTR_CEE_APP_TABLE];
		if (app_nest)
			cgdcbx_parse_cee_app_table(iface, app_nest);
	}

	return MNL_CB_OK;
}

static void cgdcbx_app_print(struct cgdcbx_entry *entry)
{
	if (entry->app.selector == 1)
		fprintf(stdout, " (%i, %i, 0x%04x)",
			entry->app.priority,
			entry->app.selector,
			entry->app.protocol);
	else
		fprintf(stdout, " (%i, %i, %i)",
			entry->app.priority,
			entry->app.selector,
			entry->app.protocol);
}

static void cgdcbx_usr1_signal()
{
	struct cgdcbx_iface *np;
	struct cgdcbx_entry *entry;
	struct cgdcbx_virt *virt;

	fprintf(stdout, "cgdcbx --- ifname: (priority, selector, protocol)\n");

	LIST_FOREACH(np, &iface_list, entry) {
		fprintf(stdout, "%s:", np->ifname);
		LIST_FOREACH(entry, &np->apps, entry) {
			cgdcbx_app_print(entry);
		}

		if (!LIST_EMPTY(&np->virt)) {
			fprintf(stdout, "\n  virt: ");
			LIST_FOREACH(virt, &np->virt, entry) {
				fprintf(stdout, " %s", virt->ifname);
			}
		}
		fprintf(stdout, "\n");
	}
}

static void cgdcbx_init_tables(struct mnl_socket *nl)
{
	struct if_nameindex *nameidx, *p;
	struct nlmsghdr *nlh;
	struct dcbmsg *dcb;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	unsigned int seq, portid;
	int ret;
	__u8 mode = 0;

	nameidx = if_nameindex();
	if (nameidx == NULL) {
		fprintf(stderr, "cgdcbx: if_nameindex() error\n");
		return;
	}

	portid = mnl_socket_get_portid(nl);
	p = nameidx;

	while (p->if_index != 0) {
		memset(buf, 0, sizeof(buf));
		nlh = mnl_nlmsg_put_header(buf);
		nlh->nlmsg_type = RTM_GETDCB;
		nlh->nlmsg_flags = NLM_F_REQUEST;
		nlh->nlmsg_seq = seq = time(NULL);

		dcb = mnl_nlmsg_put_extra_header(nlh, sizeof(struct dcbmsg));
		dcb->dcb_family = AF_UNSPEC;
		dcb->cmd = DCB_CMD_GDCBX;
		dcb->dcb_pad = 0;

		mnl_attr_put(nlh,
			     DCB_ATTR_IFNAME,
			     strlen(p->if_name) + 1,
			     p->if_name);

		if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
			perror("cgdcbx: init_tables, mnl_socket_send");
			goto index_failure;
		}

		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
		if (ret > 0)
			mnl_cb_run(buf, ret, 0, portid,
				   cgdcbx_getdcbx_reply, &mode);

		memset(buf, 0, sizeof(buf));
		nlh = mnl_nlmsg_put_header(buf);
		nlh->nlmsg_type = RTM_GETDCB;
		nlh->nlmsg_flags = NLM_F_REQUEST;
		nlh->nlmsg_seq = seq = time(NULL);

		dcb = mnl_nlmsg_put_extra_header(nlh, sizeof(struct dcbmsg));
		dcb->dcb_family = AF_UNSPEC;
		dcb->dcb_pad = 0;
		if (mode == DCB_CAP_DCBX_VER_CEE)
			dcb->cmd = DCB_CMD_CEE_GET;
		else
			dcb->cmd = DCB_CMD_IEEE_GET;

		mnl_attr_put(nlh,
			     DCB_ATTR_IFNAME,
			     strlen(p->if_name) + 1,
			     p->if_name);

		if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
			perror("cgdcbx: init_tables, mnl_socket_send");
			goto index_failure;
		}

		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
		if (ret > 0)
			mnl_cb_run(buf, ret, 0, portid, cgdcbx_dcb_cb, NULL);
index_failure:
		p++;
	}

	if_freenameindex(nameidx);
}

static void cgdcbxd_sock_init(struct mnl_socket **nl, int groups)
{
	*nl = mnl_socket_open(NETLINK_ROUTE);
	if (*nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(*nl, groups, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char *argv[])
{
	int ret, err;
	int c;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	unsigned int groups;
	unsigned char daemonize = 1;
	int nlfd_dcb, nlfd_rt, max_fd, pidfd;
	int rcv_size = 8192;
	fd_set fds, readfds;
	sigset_t sigset;
	struct cgroup_mount_point info;
	void *handle;
	static struct mnl_socket *nl_dcb, *nl_rt;
	struct sigaction sa_usr1, sa_int;
	struct option longopts[] = {
			{ 0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "vhns", longopts, NULL)) > 0) {
		switch (c) {
		case 'h':
			usage(argv[0]);
			exit(0);
		case 'n':
			daemonize = 0;
			break;
		case 'v':
			printf("%s\n", PACKAGE_STRING);
			exit(0);
		default:
			exit(1);
		}
	}

	groups = 1 << (RTNLGRP_DCB - 1);
	cgdcbxd_sock_init(&nl_dcb, groups);

	groups = 1 << (RTNLGRP_LINK - 1);
	cgdcbxd_sock_init(&nl_rt, groups);

	ret = cgroup_init();
	if (ret) {
		fprintf(stderr, "%s: libcgroup initialization failed: %s\n",
			argv[0], cgroup_strerror(ret));
		exit(EXIT_FAILURE);
	}

	err = cgroup_get_controller_begin(&handle, &info);
	while (!err) {
		if (strcmp(NET_PRIO, info.name) == 0)
			break;
		err = cgroup_get_controller_next(&handle, &info);
	}

	if (err == ECGEOF) {
		fprintf(stderr, "%s: net_prio cgroup not mounted: %s\n",
			argv[0], cgroup_strerror(err));
		exit(EXIT_FAILURE);
	}

	nlfd_dcb = mnl_socket_get_fd(nl_dcb);
	nlfd_rt = mnl_socket_get_fd(nl_rt);
	FD_ZERO(&readfds);
	FD_SET(nlfd_dcb, &readfds);
	FD_SET(nlfd_rt, &readfds);

	setsockopt(nlfd_dcb, SOL_SOCKET, SO_RCVBUF, &rcv_size, sizeof(int));
	setsockopt(nlfd_rt, SOL_SOCKET, SO_RCVBUF, &rcv_size, sizeof(int));

	memset(&sa_usr1, 0, sizeof(sa_usr1));
	sa_usr1.sa_handler = &cgdcbx_usr1_signal;
	sigemptyset(&sa_usr1.sa_mask);
	err = sigaction(SIGUSR1, &sa_usr1, NULL);
	if (err) {
		fprintf(stderr, "Failed to set up signal hander for SIGUSR1."
				" Error: %s:",
			strerror(errno));
		goto err;
	}

	memset(&sa_int, 0, sizeof(sa_int));
	sa_int.sa_handler = &cgdcbx_int_signal;
	sigemptyset(&sa_int.sa_mask);
	err = sigaction(SIGINT, &sa_int, NULL);
	err |= sigaction(SIGTERM, &sa_int, NULL);
	if (err) {
		fprintf(stderr, "Failed to set up signal hander for SIGINT."
				" Error: %s:",
			strerror(errno));
		goto err;
	}

	pidfd = open(PID_FILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (pidfd < 0) {
		fprintf(stderr, "cgdcbx: Error opening lock file");
		goto err;
	}

	errno = 0;
	if (flock(pidfd, LOCK_EX | LOCK_NB) < 0) {
		if (errno == EWOULDBLOCK) {
			char buf[256] = { 0 };

			ret = read(pidfd, buf, sizeof(buf));
			fprintf(stderr, "cgdcbx: already running pid = %s\n",
				ret > 0 ? buf : "<unknown>");
		} else {
			perror("cgdcbx: flock error:");
		}
		goto pidfd_err;
	}

	if (daemonize) {
		char buf[256] = { 0 };

		errno = 0;
		err = daemon(1, 0);
		if (err) {
			fprintf(stderr, "Failed to daemonize, Error: %s",
				strerror(errno));
			goto err;
		}

		snprintf(buf, sizeof(buf), "%u\n", getpid());
		errno = 0;
		err = write(pidfd, buf, sizeof(buf));
		if (err < 0) {
			fprintf(stderr, "Failed to write pid, Error: %s",
				strerror(errno));
			goto err;
		}
	}

	/* SIGUSR1 can not be handled while manipulating data structures
	 * while processing netlink messages
	 */
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGUSR1);

	sigprocmask(SIG_BLOCK, &sigset, NULL);
	/* Find DCB enabled interfaces */
	cgdcbx_init_tables(nl_dcb);
	/* Find any stacked interfaces */
	cgdcbx_populate_virtual_devs();
	/* Set priority on stacked devices */
	cgdcbx_update_iface_cg_all();
	sigprocmask(SIG_UNBLOCK, &sigset, NULL);

	max_fd = (nlfd_rt > nlfd_dcb) ? nlfd_rt : nlfd_dcb;

	for (;;) {
		memcpy(&fds, &readfds, sizeof(fd_set));
		errno = 0;
		err = select(max_fd + 1, &fds, NULL, NULL, NULL);
		if (err < 0 && errno != EINTR) {
			fprintf(stderr,
				"selecting error: %s\n",
				strerror(errno));
			goto err;
		} else if (errno != EINTR && FD_ISSET(nlfd_dcb, &fds)) {
			sigprocmask(SIG_BLOCK, &sigset, NULL);
			ret = mnl_socket_recvfrom(nl_dcb, buf, sizeof(buf));
			ret = mnl_cb_run(buf, ret, 0, 0, cgdcbx_dcb_cb, NULL);
			sigprocmask(SIG_UNBLOCK, &sigset, NULL);
		} else if (errno != EINTR && FD_ISSET(nlfd_rt, &fds)) {
			struct cgdcbx_link_data data = {.iface = NULL,
							.virt = NULL,
							.nlmsg_type = 0};

			ret = mnl_socket_recvfrom(nl_rt, buf, sizeof(buf));
			ret = mnl_cb_run(buf, ret, 0, 0,
					 cgdcbx_link_cb, &data);

			if ((data.ifi_flags & IFF_RUNNING) &&
			    (data.nlmsg_type != RTM_DELLINK) &&
			    data.iface) {
				cgdcbx_update_iface_cg(data.iface);
#ifdef HAVE_CGROUP_CHANGE_ALL_CGROUPS
				cgroup_change_all_cgroups();
#endif
			} else if ((data.nlmsg_type == RTM_DELLINK) && data.iface) {
				cgdcbx_free_iface(data.iface, data.virt);
			}
		}

		if (ret < MNL_CB_STOP)
			fprintf(stderr, "mnl_cb_run error: %s\n",
				strerror(errno));
	}

pidfd_err:
	close(pidfd);
err:
	if (ret == -1) {
		perror("error");
		exit(EXIT_FAILURE);
	}

	mnl_socket_close(nl_dcb);
	mnl_socket_close(nl_rt);
	return 0;
}
