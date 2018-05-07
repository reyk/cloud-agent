/*	$OpenBSD: json.c,v 1.9 2017/01/24 13:32:55 jsing Exp $ */

/*
 * Copyright (c) 2016 Kristaps Dzonsons <kristaps@bsd.lv>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <assert.h>
#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "jsmn.h"
#include "main.h"

struct	jsmnp;

/*
 * Objects consist of node pairs: the left-hand side (before the colon)
 * and the right-hand side---the data.
 */
struct	jsmnp {
	struct jsmnn	*lhs; /* left of colon */
	struct jsmnn	*rhs; /* right of colon */
};

/*
 * Object for converting the JSMN token array into a tree.
 */
struct	parse {
	struct jsmnn	*nodes; /* all nodes */
	size_t		 cur; /* current number */
	size_t		 max; /* nodes in "nodes" */
};

/*
 * Recursive part for convertin a JSMN token array into a tree.
 * See "example/jsondump.c" for its construction (it's the same except
 * for how it handles allocation errors).
 */
static ssize_t
build(struct parse *parse, struct jsmnn **np,
    jsmntok_t *t, const char *js, size_t sz)
{
	size_t		 i, j;
	struct jsmnn	*n;
	ssize_t		 tmp;

	if (sz == 0)
		return 0;

	assert(parse->cur < parse->max);
	n = *np = &parse->nodes[parse->cur++];
	n->p = parse;
	n->type = t->type;

	switch (t->type) {
	case JSMN_STRING:
		/* FALLTHROUGH */
	case JSMN_PRIMITIVE:
		n->fields = 1;
		n->d.str = strndup
			(js + t->start,
			 t->end - t->start);
		if (n->d.str == NULL)
			break;
		return 1;
	case JSMN_OBJECT:
		n->fields = t->size;
		n->d.obj = calloc(n->fields,
			sizeof(struct jsmnp));
		if (n->d.obj == NULL)
			break;
		for (i = j = 0; i < (size_t)t->size; i++) {
			tmp = build(parse,
				&n->d.obj[i].lhs,
				t + 1 + j, js, sz - j);
			if (tmp < 0)
				break;
			j += tmp;
			tmp = build(parse,
				&n->d.obj[i].rhs,
				t + 1 + j, js, sz - j);
			if (tmp < 0)
				break;
			j += tmp;
		}
		if (i < (size_t)t->size)
			break;
		return j + 1;
	case JSMN_ARRAY:
		n->fields = t->size;
		n->d.array = calloc(n->fields,
			sizeof(struct jsmnn *));
		if (n->d.array == NULL)
			break;
		for (i = j = 0; i < (size_t)t->size; i++) {
			tmp = build(parse,
				&n->d.array[i],
				t + 1 + j, js, sz - j);
			if (tmp < 0)
				break;
			j += tmp;
		}
		if (i < (size_t)t->size)
			break;
		return j + 1;
	default:
		break;
	}

	return -1;
}

/*
 * Fully free up a parse sequence.
 * This handles all nodes sequentially, not recursively.
 */
static void
jsmnparse_free(struct parse *p)
{
	size_t	 i;

	if (p == NULL)
		return;
	for (i = 0; i < p->max; i++) {
		struct jsmnn	*n = &p->nodes[i];
		switch (n->type) {
		case JSMN_ARRAY:
			free(n->d.array);
			break;
		case JSMN_OBJECT:
			free(n->d.obj);
			break;
		case JSMN_PRIMITIVE:
			free(n->d.str);
			break;
		case JSMN_STRING:
			free(n->d.str);
			break;
		case JSMN_UNDEFINED:
			break;
		}
	}
	free(p->nodes);
	free(p);
}

/*
 * Allocate a tree representation of "t".
 * This returns NULL on allocation failure or when sz is zero, in which
 * case all resources allocated along the way are freed already.
 */
static struct jsmnn *
jsmntree_alloc(jsmntok_t *t, const char *js, size_t sz)
{
	struct jsmnn	*first;
	struct parse	*p;

	if (sz == 0)
		return NULL;

	p = calloc(1, sizeof(struct parse));
	if (p == NULL)
		return NULL;

	p->max = sz;
	p->nodes = calloc(p->max, sizeof(struct jsmnn));
	if (p->nodes == NULL) {
		free(p);
		return NULL;
	}

	if (build(p, &first, t, js, sz) < 0) {
		jsmnparse_free(p);
		first = NULL;
	}

	return first;
}

/*
 * Call through to free parse contents.
 */
void
json_free(struct jsmnn *first)
{

	if (first != NULL)
		jsmnparse_free(first->p);
}

/*
 * Just check that the array object is in fact an object.
 */
struct jsmnn *
json_getarrayobj(struct jsmnn *n)
{

	return n->type != JSMN_OBJECT ? NULL : n;
}

/*
 * Extract an array from the returned JSON object, making sure that it's
 * the correct type.
 * Returns NULL on failure.
 */
struct jsmnn *
json_getarray(struct jsmnn *n, const char *name)
{
	size_t		 i;

	if (n->type != JSMN_OBJECT)
		return NULL;
	for (i = 0; i < n->fields; i++) {
		if (n->d.obj[i].lhs->type != JSMN_STRING &&
		    n->d.obj[i].lhs->type != JSMN_PRIMITIVE)
			continue;
		else if (strcmp(name, n->d.obj[i].lhs->d.str))
			continue;
		break;
	}
	if (i == n->fields)
		return NULL;
	if (n->d.obj[i].rhs->type != JSMN_ARRAY)
		return NULL;
	return n->d.obj[i].rhs;
}

/*
 * Extract a single string from the returned JSON object, making sure
 * that it's the correct type.
 * Returns NULL on failure.
 */
char *
json_getstr(struct jsmnn *n, const char *name)
{
	size_t		 i;
	char		*cp;

	if (n->type != JSMN_OBJECT)
		return NULL;
	for (i = 0; i < n->fields; i++) {
		if (n->d.obj[i].lhs->type != JSMN_STRING &&
		    n->d.obj[i].lhs->type != JSMN_PRIMITIVE)
			continue;
		else if (strcmp(name, n->d.obj[i].lhs->d.str))
			continue;
		break;
	}
	if (i == n->fields)
		return NULL;
	if (n->d.obj[i].rhs->type != JSMN_STRING &&
	    n->d.obj[i].rhs->type != JSMN_PRIMITIVE)
		return NULL;

	cp = strdup(n->d.obj[i].rhs->d.str);
	if (cp == NULL)
		warn("strdup");
	return cp;
}

/*
 * Parse an HTTP response body from a buffer of size "sz".
 * Returns an opaque pointer on success, otherwise NULL on error.
 */
struct jsmnn *
json_parse(const char *buf, size_t sz)
{
	struct jsmnn	*n;
	jsmn_parser	 p;
	jsmntok_t	*tok;
	int		 r;
	size_t		 tokcount;

	jsmn_init(&p);
	tokcount = 128;

	/* Do this until we don't need any more tokens. */
again:
	tok = calloc(tokcount, sizeof(jsmntok_t));
	if (tok == NULL) {
		warn("calloc");
		return NULL;
	}

	/* Actually try to parse the JSON into the tokens. */

	r = jsmn_parse(&p, buf, sz, tok, tokcount);
	if (r < 0 && r == JSMN_ERROR_NOMEM) {
		tokcount *= 2;
		free(tok);
		goto again;
	} else if (r < 0) {
		warnx("jsmn_parse: %d", r);
		free(tok);
		return NULL;
	}

	/* Now parse the tokens into a tree. */

	n = jsmntree_alloc(tok, buf, r);
	free(tok);
	return n;
}
