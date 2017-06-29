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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <ctype.h>
#include <err.h>

#include <expat.h>
#include "main.h"
#include "xml.h"

static void	 xml_start_element(void *, const char *, const char **);
static void	 xml_end_element(void *, const char *);
static void	 xml_char_data(void *, const char *, int);
static void	 xml_inc(struct xmlelem *, int);

static void
xml_inc(struct xmlelem *b, int depth)
{
	struct xmlelem	*xe;
	b->xe_depth += depth;
	TAILQ_FOREACH(xe, &b->xe_head, xe_entry)
		xml_inc(xe, depth);
}

void
xml_add(struct xmlelem *a, struct xmlelem *b)
{
	xml_inc(b, a->xe_depth);
	TAILQ_INSERT_TAIL(&a->xe_head, b, xe_entry);
}

void
xml_delete(struct xmlhead *xh)
{
	struct xmlelem	*xe, *tmp;
	int		 i;

	TAILQ_FOREACH_SAFE(xe, xh, xe_entry, tmp) {
		xml_delete(&xe->xe_head);
		TAILQ_REMOVE(xh, xe, xe_entry);

		if (xe->xe_attr != NULL) {
			for (i = 0; xe->xe_attr[i] != NULL; i++)
				free(xe->xe_attr[i]);
			free(xe->xe_attr);
		}

		free(xe->xe_data);
		free(xe->xe_tag);
		free(xe);
	}
}

struct xmlelem *
xml_get(struct xmlhead *root, const char *arg)
{
	struct xmlelem	*xe;

	TAILQ_FOREACH(xe, root, xe_entry) {
		/* search case-insensitive */
		if (strcasecmp(xe->xe_tag, arg) == 0)
			return (xe);
	}
	return (NULL);
}

struct xmlelem *
xml_findv(struct xmlhead *root, const char **argv, int argc)
{
	struct xmlelem	*xe = NULL;
	struct xmlhead	*head = root;
	int		 i;

	for (i = 0; i < argc; i++) {
		if ((xe = xml_get(head, argv[i])) == NULL)
			break;
		head = &xe->xe_head;
	}

	return (xe);
}

struct xmlelem *
xml_findl(struct xmlhead *root, const char *arg, ...)
{
	struct xmlelem	*xe = NULL;
	const char	**argv = NULL;
	int		 argc, i;
	const char	*tag;
	va_list		 ap;

	va_start(ap, arg);
	for (argc = 1; va_arg(ap, const char *) != NULL; argc++)
		;
	va_end(ap);

	if ((argv = calloc(argc, sizeof(const char *))) == NULL)
		fatal("calloc");
	i = 0;
	argv[i++] = arg;

	va_start(ap, arg);
	while ((tag = va_arg(ap, const char *)) != NULL)
		argv[i++] = tag;
	va_end(ap);

	xe = xml_findv(root, argv, argc);
	free(argv);

	return (xe);
}

/*
 * Print XML tree suitable for OVF
 *
 * This parser and printer does not support CDATA with embedded
 * elements which is not required for OVF - it is more or less a simple
 * key/value store without HTML-like markup.
 */
void
xml_print(struct xml *env, struct xmlelem *xe, int data_only, FILE *fp)
{
	struct xmlelem	*xelm;
	int		 i;

	if (xe == NULL)
		return;

	if (data_only) {
		if (xe->xe_datalen)
			fprintf(fp, "%*s\n",
			    (int)xe->xe_datalen, xe->xe_data);
		TAILQ_FOREACH(xelm, &xe->xe_head, xe_entry)
			xml_print(env, xelm, data_only, fp);
		return;
	}

	/* Print XML header for the root node */
	if (xe->xe_parent == NULL)
		fprintf(fp, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");

	fprintf(fp, "%*s<%s", xe->xe_depth * 2, "", xe->xe_tag);
	for (i = 0; xe->xe_attr[i] != NULL; i += 2) {
		fprintf(fp, " %s=\"%s\"",
		    xe->xe_attr[i], xe->xe_attr[i + 1]);
	}
	fprintf(fp, ">");

	if (xe->xe_datalen)
		fprintf(fp, "%*s",
		    (int)xe->xe_datalen, xe->xe_data);

	if (!TAILQ_EMPTY(&xe->xe_head))
		fprintf(fp, "\n");

	TAILQ_FOREACH(xelm, &xe->xe_head, xe_entry)
		xml_print(env, xelm, data_only, fp);

	if (TAILQ_EMPTY(&xe->xe_head))
		fprintf(fp, "</%s>\n", xe->xe_tag);
	else
		fprintf(fp, "%*s</%s>\n", xe->xe_depth * 2, "", xe->xe_tag);
}

/*
 * Simple XML parser
 */

static void
xml_start_element(void *data, const char *el, const char **attr)
{
	struct xml	*env = data;
	struct xmlelem	*xe;
	struct xmlhead	*xh;
	int		 i;

	if ((xe = calloc(1, sizeof(*xe))) == NULL)
		fatal("callac");
	TAILQ_INIT(&xe->xe_head);

	if (env->ox_cur == NULL)
		xh = &env->ox_root;
	else
		xh = &env->ox_cur->xe_head;

	xe->xe_parent = env->ox_cur;
	xe->xe_depth = env->ox_depth;
	if ((xe->xe_tag = strdup(el)) == NULL)
		fatal("strdup");

	TAILQ_INSERT_TAIL(xh, xe, xe_entry);
	env->ox_cur = xe;

	/* Copy attributes */
	for (i = 0; attr[i] != NULL; i += 2)
		;
	xe->xe_nattr = i / 2;

	if ((xe->xe_attr = calloc(i + 1, sizeof(char *))) == NULL)
		fatal("calloc");

	for (i = 0; attr[i] != NULL; i++) {
		if ((xe->xe_attr[i] = strdup(attr[i])) == NULL)
			fatal("strdup");
	}

	env->ox_depth++;
}

static void
xml_end_element(void *data, const char *el)
{
	struct xml	*env = data;
	struct xmlelem	*xe = env->ox_cur;

	if (xe == NULL)
		fatal("missing element");
	if (strcmp(xe->xe_tag, el) != 0)
		fatal("unexpected closing tag: %s <> %s", el, xe->xe_tag);
	if (xe->xe_data == NULL) {
		xe->xe_data = strdup("");
		xe->xe_datalen = 0;
	}

	env->ox_cur = xe->xe_parent;
	env->ox_depth--;
}

static void
xml_char_data(void *data, const char *s, int len)
{
	struct xml	*env = data;
	struct xmlelem	*xe = env->ox_cur;
	char		*p;
	int		 i;
	int		 ok = 0;
	off_t		 off = 0;

	for (i = 0; i < len && s[i] != '\0'; i++) {
		if (!isspace(s[i])) {
			ok = 1;
			break;
		}
	}

	if (!ok)
		return;

	/* XXX there might be a better way to handle libexpat cdata */
	if ((p = realloc(xe->xe_data, xe->xe_datalen + len + 2)) == NULL)
		fatal("realloc");
	if (xe->xe_datalen) {
		p[xe->xe_datalen] = '\n';
		off = 1;
	}
	memcpy(p + xe->xe_datalen + off, s, len);
	p[xe->xe_datalen + off + len] = '\0';

	xe->xe_data = p;
	xe->xe_datalen += len + off;

	env->ox_data = 1;
}

int
xml_init(struct xml *env)
{
	XML_Parser	 parser;

	memset(env, 0, sizeof(*env));
	TAILQ_INIT(&env->ox_root);

	if ((parser = XML_ParserCreate(NULL)) == NULL)
		return (-1);
	env->ox_parser = parser;

	XML_SetUserData(parser, env);
	XML_SetElementHandler(parser,
	    xml_start_element, xml_end_element);
	XML_SetCharacterDataHandler(parser, xml_char_data);

	return (0);
}

void
xml_free(struct xml *env)
{
	if (env == NULL)
		return;
	if (env->ox_parser != NULL)
		XML_ParserFree(env->ox_parser);
	xml_delete(&env->ox_root);
	memset(env, 0, sizeof(*env));
}

int
xml_parse_buffer(struct xml *env, char *xml, size_t xmllen)
{
	XML_Parser	 parser = env->ox_parser;

	if (XML_Parse(parser, xml, xmllen,
	    XML_TRUE) == XML_STATUS_ERROR)
		return (-1);

	XML_ParserFree(parser);
	env->ox_parser = NULL;

	if (TAILQ_EMPTY(&env->ox_root))
		return (-1);

	return (0);
}

int
xml_parse(struct xml *env, const char *file)
{
	XML_Parser	 parser = env->ox_parser;
	int		 fd;
	void		*xml;
	ssize_t		 len;

	if ((fd = open(file, O_RDONLY)) == -1)
		fatal("open %s", file);

	do {
		if ((xml = XML_GetBuffer(parser, BUFSIZ)) == NULL)
			fatalx("XML_GetBuffer");

		if ((len = read(fd, xml, BUFSIZ)) <= 0)
			break;

		if (XML_ParseBuffer(parser, len, XML_FALSE) == XML_STATUS_ERROR)
			fatalx("XML_ParseBuffer");
	} while (len == BUFSIZ);

	close(fd);

	if (XML_Parse(parser, NULL, 0, XML_TRUE) == XML_STATUS_ERROR)
		fatalx("XML_Parse");

	XML_ParserFree(parser);
	env->ox_parser = NULL;

	return (0);
}
