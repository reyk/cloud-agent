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

#ifndef MAIN_H
#define MAIN_H

#include <sys/queue.h>
#include <sys/cdefs.h>
#include <stdarg.h>
#include <stddef.h>

#include "http.h"

struct ssh_pubkey {
	char			*ssh_keyval;
	char			*ssh_keyfp;

	TAILQ_ENTRY(ssh_pubkey)	 ssh_entry;
};
TAILQ_HEAD(ssh_pubkeys, ssh_pubkey);

struct system_config {
	char			*sc_hostname;
	char			*sc_username;
	char			*sc_password;
	char			*sc_pubkey;
	unsigned char		*sc_userdata;
	size_t			 sc_userdatalen;
	char			*sc_endpoint;
	char			*sc_instance;

	const char		*sc_ovfenv;
	const char		*sc_interface;
	const char		*sc_cdrom;

	struct source		 sc_addr;
	struct ssh_pubkeys	 sc_pubkeys;

	int			 sc_nullfd;
	void			*sc_priv;
};

/* azure.c */
int	 azure(struct system_config *);

/* cloudinit.c */
int	 ec2(struct system_config *);
int	 cloudinit(struct system_config *);

/* main.c */
int	 shell(const char *, ...);
int	 shellout(const char *, char **, const char *, ...);
int	 disable_output(struct system_config *, int);
int	 enable_output(struct system_config *, int, int);
int	 agent_addpubkey(struct system_config *, const char *, const char *);
int	 agent_setpubkey(struct system_config *, const char *, const char *);
int	 agent_configure(struct system_config *, int);

/* log.c */
void	log_init(int, int);
void	log_procinit(const char *);
void	log_setverbose(int);
int	log_getverbose(void);
void	log_warn(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_warnx(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_info(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_debug(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	logit(int, const char *, ...)
	    __attribute__((__format__ (printf, 2, 3)));
void	vlog(int, const char *, va_list)
	    __attribute__((__format__ (printf, 2, 0)));
__dead void fatal(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
__dead void fatalx(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));

#endif /* MAIN_H */
