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

int
tryendpoint(struct system_config *sc,
    int (fetch)(struct system_config *),
    int (next)(struct system_config *))
{
	free(sc->sc_endpoint);
	sc->sc_endpoint = NULL;

	switch (sc->sc_dhcpendpoint) {
	case 0:
		sc->sc_dhcpendpoint = 1;
		if (dhcp_getendpoint(sc) == -1)
			return tryendpoint(sc, fetch, next);
		break;
	case 1:
		sc->sc_dhcpendpoint = 2;
		if ((sc->sc_endpoint = strdup(DEFAULT_ENDPOINT)) == NULL) {
			log_warnx("failed to set defaults");
			return (-1);
		}
		break;
	default:
		if (next == NULL)
			return (-1);
		sc->sc_dhcpendpoint = 0;
		return (*next)(sc);
	}

	if ((*fetch)(sc) != 0)
		return tryendpoint(sc, fetch, next);

	return (0);
}

int
ec2(struct system_config *sc)
{
	free(sc->sc_username);
	if ((sc->sc_username = strdup("ec2-user")) == NULL) {
		log_warnx("failed to set default user");
		return (-1);
	}

	sc->sc_stack = "ec2";
	sc->sc_dhcpendpoint = 1;
	return tryendpoint(sc, cloudinit_fetch, NULL);
}

int
cloudinit(struct system_config *sc)
{
	sc->sc_stack = "cloudinit";
	sc->sc_dhcpendpoint = 0;
	return tryendpoint(sc, cloudinit_fetch, NULL);
}

static int
cloudinit_fetch(struct system_config *sc)
{
	int		 ret = -1;
	char		*str = NULL;

	sc->sc_addr.ip = sc->sc_endpoint;
	sc->sc_addr.family = 4;

	/* instance-id */
	if ((sc->sc_instance = metadata(sc,
	    "/latest/meta-data/instance-id", WORD)) == NULL)
		goto fail;

	/* hostname */
	if ((sc->sc_hostname = metadata(sc,
	    "/latest/meta-data/local-hostname", WORD)) == NULL)
		goto fail;

	/* optional pubkey */
	if ((str = metadata(sc,
	    "/latest/meta-data/public-keys/0/openssh-key", LINE)) == NULL &&
	    (str = metadata(sc,
	    "/latest/meta-data/public-keys", LINE)) == NULL)
		log_warnx("failed to get public key");
	else if (agent_addpubkey(sc, str, NULL) != 0)
		goto fail;

	/* optional username - this is an extension by meta-data(8) */
	if ((str = metadata(sc, "/latest/meta-data/username", WORD)) != NULL) {
		free(sc->sc_username);
		sc->sc_username = str;
		str = NULL;
	}

	/* userdata (optional) */
	sc->sc_userdata = metadata(sc, "/latest/user-data", TEXT);

	ret = 0;
 fail:
	free(str);
	return (ret);
}
