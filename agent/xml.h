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

#ifndef OVFXML_H
#define OVFXML_H

#include <sys/queue.h>

#include <stddef.h>

TAILQ_HEAD(xmlhead, xmlelem);

struct xmlelem {
	char			 *xe_tag;
	char			**xe_attr;
	unsigned int		  xe_nattr;
	unsigned int		  xe_depth;
	char			 *xe_data;
	size_t			  xe_datalen;
	struct xmlelem		 *xe_parent;
	struct xmlhead		  xe_head;
	TAILQ_ENTRY(xmlelem)	  xe_entry;
};

struct xml {
	int			  ox_depth;
	int			  ox_data;
	struct xmlhead		  ox_root;
	struct xmlelem		 *ox_cur;
	struct xmlelem		 *ox_prev;
	void			 *ox_parser;
};

int		 xml_init(struct xml *);
void		 xml_free(struct xml *);
void		 xml_add(struct xmlelem *, struct xmlelem *);
void		 xml_delete(struct xmlhead *);
struct xmlelem	*xml_get(struct xmlhead *, const char *);
struct xmlelem	*xml_findv(struct xmlhead *, const char **, int);
struct xmlelem	*xml_findl(struct xmlhead *, const char *, ...);
void		 xml_print(struct xml *, struct xmlelem *, int, FILE *);
int		 xml_parse_buffer(struct xml *, char *, size_t);
int		 xml_parse(struct xml *, const char *);

#endif /* OVFXML_H */
