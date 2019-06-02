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
#include <sys/socket.h>
#include <stdarg.h>
#include <stddef.h>

#include "http.h"
#include "jsmn.h"

#define DEFAULT_ENDPOINT	"169.254.169.254"
#define CONNECT_TIMEOUT		10 /* in seconds */

enum strtype {
	WORD,
	LINE,
	TEXT
};

struct ssh_pubkey {
	char			*ssh_keyval;
	char			*ssh_keyfp;

	TAILQ_ENTRY(ssh_pubkey)	 ssh_entry;
};
TAILQ_HEAD(ssh_pubkeys, ssh_pubkey);

enum net_type {
	NET_IP,
	NET_MASK,
	NET_PREFIX,
	NET_MAC,
	NET_MTU,
	NET_GATEWAY,
	NET_DNS,
	NET_DNS_DOMAIN,
	NET_MAX
};

struct net_addr {
	enum net_type		 net_type;
	unsigned short		 net_ifunit;
	char			*net_value;
	struct sockaddr_storage	 net_addr;
	unsigned int		 net_num;

	TAILQ_ENTRY(net_addr)	 net_entry;
};
TAILQ_HEAD(net_addrs, net_addr);

struct system_config {
	const char		*sc_stack;
	char			*sc_args;

	char			*sc_hostname;
	char			*sc_username;
	char			*sc_password;
	char			*sc_pubkey;
	char			*sc_userdata;
	char			*sc_endpoint;
	int			 sc_dhcpendpoint;
	char			*sc_instance;
	int			 sc_timeout;

	const char		*sc_ovfenv;
	const char		*sc_interface;
	const char		*sc_cdrom;
	const char		*sc_rootdisk;
	int			 sc_mount;

	struct source		 sc_addr;
	struct ssh_pubkeys	 sc_pubkeys;

	int			 sc_network;
	struct net_addrs	 sc_netaddrs;
	unsigned int		 sc_netmtu;

	int			 sc_nullfd;
	int			 sc_dryrun;
	void			*sc_priv;
};

struct	jsmnp;
struct	jsmnn {
	struct parse		*p;
	union {
		char		*str;
		struct jsmnp	*obj;
		struct jsmnn	**array;
	} d;
	size_t			 fields;
	jsmntype_t		 type;
};

/* json.c */
struct jsmnn	*json_parse(const char *, size_t);
void		 json_free(struct jsmnn *);
struct jsmnn	*json_getarrayobj(struct jsmnn *);
struct jsmnn	*json_getarray(struct jsmnn *, const char *);
struct jsmnn	*json_getobj(struct jsmnn *, const char *);
char		*json_getstr(struct jsmnn *, const char *);

/* azure.c */
int	 azure(struct system_config *);

/* cloudinit.c */
int	 ec2(struct system_config *);
int	 cloudinit(struct system_config *);
int	 tryendpoint(struct system_config *,
	    int (fetch)(struct system_config *),
	    int (next)(struct system_config *));

/* opennebula.c */
int	 opennebula(struct system_config *);

/* openstack.c */
int	 openstack(struct system_config *);

/* growdisk.c */
int	 growdisk(struct system_config *);

/* main.c */
int	 shell(const char *, ...);
int	 shellout(const char *, char **, const char *, ...);
int	 disable_output(struct system_config *, int);
int	 enable_output(struct system_config *, int, int);
char	*get_string(const unsigned char *, size_t);
char	*get_line(const unsigned char *, size_t);
char	*get_word(const unsigned char *, size_t);
int	 agent_addpubkey(struct system_config *, const char *, const char *);
int	 agent_setpubkey(struct system_config *, const char *, const char *);
struct net_addr *
	 agent_getnetaddr(struct system_config *, struct net_addr *);
int	 agent_addnetaddr(struct system_config *, unsigned int,
	    const char *, int, enum net_type);
char	*metadata(struct system_config *, const char *, enum strtype);
char	*metadata_file(struct system_config *, const char *, enum strtype);
int	 connect_wait(int, const struct sockaddr *, socklen_t);
int	 dhcp_getendpoint(struct system_config *);

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
