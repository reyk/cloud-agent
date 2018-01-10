/*
 * Copyright (c) 2018 Reyk Floeter <reyk@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/queue.h>
#include <sys/stat.h>

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>

#include "main.h"
#include "http.h"
#include "xml.h"

static int	 openstack_fetch(struct system_config *);

int
openstack(struct system_config *sc)
{
	if ((dhcp_getendpoint(sc) == -1) &&
	    (sc->sc_endpoint = strdup(DEFAULT_ENDPOINT)) == NULL) {
		log_warnx("failed to set defaults");
		return (-1);
	}

	if (openstack_fetch(sc) != 0) {
		free(sc->sc_endpoint);
		return (cloudinit(sc));
	}
	return (0);
}

static int
openstack_fetch(struct system_config *sc)
{
	int		 ret = -1;
	char		*json = NULL, *str;
	struct jsmnn	*j = NULL, *o, *f;
	size_t		 i;

	sc->sc_addr.ip = sc->sc_endpoint;
	sc->sc_addr.family = 4;

	/* meta_data, we don't handle vendor_data */
	if ((json = metadata(sc,
	    "/openstack/latest/meta_data.json", TEXT)) == NULL)
		goto fail;

	if ((j = json_parse(json, strlen(json))) == NULL)
		goto fail;

	/* instance-id */
	if ((sc->sc_instance = json_getstr(j, "uuid")) == NULL)
		goto fail;

	/* hostname */
	if ((sc->sc_hostname = json_getstr(j, "hostname")) == NULL)
		goto fail;

	/* public keys */
	if ((o = json_getarray(j, "keys")) == NULL)
		goto fail;
	for (i = 0; i < o->fields; i++) {
		if ((f = json_getarrayobj(o->d.array[i])) == NULL)
			continue;
		if ((str = json_getstr(f, "data")) == NULL)
			continue;
		if (agent_addpubkey(sc, str, NULL) != 0) {
			free(str);
			goto fail;
		}
		free(str);
	}

	/* userdata (optional) */
	sc->sc_userdata = metadata(sc, "/openstack/latest/user_data", TEXT);

	ret = 0;
 fail:
	json_free(j);
	free(json);
	return (ret);
}
