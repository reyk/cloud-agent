/*
 * Copyright (c) 2017 Reyk Floeter <reyk@openbsd.org>
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

static int	 cloudinit_fetch(struct system_config *);
static char	*cloudinit_get(struct system_config *, const char *, size_t *);

int
ec2(struct system_config *sc)
{
	if ((sc->sc_username = strdup("ec2-user")) == NULL ||
	    (sc->sc_endpoint = strdup("169.254.169.254")) == NULL) {
		log_warnx("failed to set defaults");
		return (-1);
	}

	return (cloudinit_fetch(sc));
}

int
cloudinit(struct system_config *sc)
{
	/* XXX get endpoint from DHCP lease file */
	if ((sc->sc_username = strdup("puffy")) == NULL ||
	    (sc->sc_endpoint = strdup("169.254.169.254")) == NULL) {
		log_warnx("failed to set defaults");
		return (-1);
	}

	return (cloudinit_fetch(sc));
}

static char *
cloudinit_get(struct system_config *sc, const char *path, size_t *strsz)
{
	struct httpget	*g = NULL;
	char		*str = NULL;

	log_debug("%s: %s", __func__, path);

	g = http_get(&sc->sc_addr, 1,
	    sc->sc_endpoint, 80, path, NULL, 0, NULL);
	if (g != NULL && g->code == 200 && g->bodypartsz > 0) {
		if ((str = calloc(1, g->bodypartsz + 1)) != NULL) {
			memcpy(str, g->bodypart, g->bodypartsz);
			if (strsz != NULL)
				*strsz = g->bodypartsz;
		}
	}
	http_get_free(g);

	return (str);
}

static int
cloudinit_fetch(struct system_config *sc)
{
	int		 ret = 0;
	char		*str = NULL;

	sc->sc_addr.ip = sc->sc_endpoint;
	sc->sc_addr.family = 4;

	/* instance-id */
	if ((sc->sc_instance = cloudinit_get(sc,
	    "/latest/meta-data/instance-id", NULL)) == NULL)
		goto fail;

	/* hostname */
	if ((sc->sc_hostname = cloudinit_get(sc,
	    "/latest/meta-data/local-hostname", NULL)) == NULL)
		goto fail;

	/* pubkey */
	if ((str = cloudinit_get(sc,
	    "/latest/meta-data/public-keys/0/openssh-key", NULL)) == NULL)
		goto fail;
	if (agent_addpubkey(sc, str, NULL) != 0)
		goto fail;

	/* optional username - this is an extension by meta-data(8) */
	if ((str = cloudinit_get(sc,
	    "/latest/meta-data/username", NULL)) != NULL) {
		free(sc->sc_username);
		sc->sc_username = str;
	}

	/* userdata */
	if ((sc->sc_userdata = cloudinit_get(sc,
	    "/latest/user-data", &sc->sc_userdatalen)) == NULL)
		goto fail;

	ret = 0;
 fail:
	free(str);
	return (ret);
}
