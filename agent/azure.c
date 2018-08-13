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

static struct azure_config {
	const char	*az_apiversion;
	unsigned int	 az_incarnation;
	const char	*az_privkey;
	const char	*az_pubkey;
	const char	*az_certs;
	char		*az_pubkeyval;
	char		*az_container;
} az_config = {
	.az_apiversion	= "2015-04-05",
	.az_incarnation	= 1,
	.az_privkey	= "/var/db/azure-transport.key",
	.az_pubkey	= "/var/db/azure-transport.pub",
	.az_certs	= "/var/db/azure-certificates.pem"
};

static struct httpget
		*azure_request(struct system_config *, struct xml *,
		    const char *, const void *, size_t, struct httphead **);

static int	 azure_keys(struct system_config *);
static int	 azure_getpubkeys(struct system_config *);
static int	 azure_getovfenv(struct system_config *);
static int	 azure_versions(struct system_config *);
static int	 azure_goalstate(struct system_config *);
static int	 azure_certificates(struct system_config *);
static int	 azure_reporthealth(struct system_config *, const char *);

int
azure(struct system_config *sc)
{
	int	 ret = -1;

	sc->sc_stack = "azure";

	/* Apply defaults */
	free(sc->sc_username);
	if ((sc->sc_username = strdup("azure-user")) == NULL) {
		log_warnx("failed to set default user");
		goto fail;
	}
	sc->sc_ovfenv = "/var/db/azure-ovf-env.xml";
	sc->sc_priv = &az_config;

	if (azure_getovfenv(sc) != 0) {
		log_warnx("failed to get ovf-env.xml");
		goto fail;
	}

	if (dhcp_getendpoint(sc) != 0) {
		log_warnx("failed to get endpoint");
		goto fail;
	}

	if (azure_versions(sc) != 0) {
		log_warnx("failed to get endpoint versions");
		goto fail;
	}

	if (azure_goalstate(sc) != 0) {
		log_warnx("failed to get goalstate");
		goto fail;
	}

	if (!sc->sc_dryrun) {
		if (azure_keys(sc) != 0) {
			log_warnx("failed to get transport keys");
			goto fail;
		}

		if (azure_certificates(sc) != 0) {
			log_warnx("failed to get certificates");
			goto fail;
		}
	}

	if (azure_reporthealth(sc, "Ready") != 0) {
		log_warnx("failed to report health");
		goto fail;
	}

	ret = 0;
 fail:
	free(az_config.az_container);
	free(az_config.az_pubkeyval);

	return (ret);
}

int
azure_keys(struct system_config *sc)
{
	struct azure_config	*az = sc->sc_priv;
	int			 fd, i;
	const char		*k[4];
	FILE			*fp = NULL, *keyfp = NULL;
	char			 buf[BUFSIZ];
	char			*keybuf = NULL;
	size_t			 keybufsz;

	k[0] = az->az_privkey;
	k[1] = az->az_pubkey;
	k[2] = az->az_certs;
	k[3] = NULL;

	if (access(az->az_privkey, R_OK) != 0 ||
	    access(az->az_pubkey, R_OK) != 0) {
		/* Ugh, we must generate the files before writing the keys */
		for (i = 0; k[i] != NULL; i++) {
			if ((fd = open(k[i],
			    O_WRONLY|O_CREAT|O_TRUNC, 0600)) == -1)
				return (-1);
			close(fd);
		}

		fd = disable_output(sc, STDERR_FILENO);

		/* Now generate the actual transport keys */
		if (shell("openssl", "req",
		    "-x509", "-nodes", "-subj", "/CN=LinuxTransport",
		    "-days", "32768", "-newkey", "rsa:2048",
		    "-keyout", az->az_privkey,
		    "-out", az->az_pubkey,
		    NULL) != 0) {
			log_debug("%s: failed to generate keys", __func__);
			return (-1);
		}

		enable_output(sc, STDERR_FILENO, fd);
	}

	if ((fp = fopen(az->az_pubkey, "r")) == NULL) {
		log_debug("%s: failed to read public key", __func__);
		goto done;
	}

	if ((keyfp = open_memstream(&keybuf, &keybufsz)) == NULL) {
		log_debug("%s: failed to open public key stream", __func__);
		goto done;
	}

	/* We have to read the public key into a single base64 line */
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		buf[strcspn(buf, "\r\n")] = '\0';

		if (strcmp("-----BEGIN CERTIFICATE-----", buf) == 0 ||
		    strcmp("-----END CERTIFICATE-----", buf) == 0 ||
		    strlen(buf) < 1)
			continue;

		if (fputs(buf, keyfp) < 0) {
			log_debug("%s: failed to write public key",
			    __func__);
			goto done;
		}
	}

	fclose(keyfp);
	keyfp = NULL;

	az->az_pubkeyval = keybuf;

 done:
	if (fp != NULL)
		fclose(fp);
	if (keyfp != NULL) {
		fclose(keyfp);
		free(keybuf);
	}

	return (0);
}

struct httpget *
azure_request(struct system_config *sc, struct xml *xml, const char *path,
    const void *post, size_t postsz, struct httphead **head)
{
	struct azure_config	*az = sc->sc_priv;
	struct httpget		*g = NULL;
	struct httphead		**reqhead = NULL;
	int			 i;

	if (xml != NULL && xml_init(xml) != 0)
		return (NULL);

	for (i = 0; head != NULL && head[i] != NULL; i++)
		;
	if ((reqhead = calloc(i + 3, sizeof(struct httphead *))) == NULL) {
		log_debug("%s: head", __func__);
		goto fail;
	}
	for (i = 0; head != NULL && head[i] != NULL; i++)
		reqhead[i] = head[i];
	reqhead[i++] = &(struct httphead){ "x-ms-agent-name", "cloud-agent" };
	reqhead[i++] = &(struct httphead){ "x-ms-version", az->az_apiversion };
	reqhead[i++] = NULL;

	g = http_get(&sc->sc_addr, 1,
	    sc->sc_endpoint, 80, path, post, postsz, reqhead);
	if (g == NULL || g->code != 200) {
		log_debug("%s: invalid response", __func__);
		goto fail;
	}
	free(reqhead);

	if (xml == NULL) {
		if (log_getverbose() > 2)
			fwrite(g->bodypart, g->bodypartsz, 1, stderr);
		return (g);
	}

	if (g->bodypartsz < 1 ||
	    xml_parse_buffer(xml, g->bodypart, g->bodypartsz) != 0) {
		log_debug("%s: xml", __func__);
		goto fail;
	}

	if (log_getverbose() > 2)
		xml_print(xml, TAILQ_FIRST(&xml->ox_root), 0, stderr);

	return (g);

 fail:
	xml_free(xml);
	if (reqhead != NULL)
		free(reqhead);
	if (g != NULL)
		http_get_free(g);
	return (NULL);
}

static int
azure_versions(struct system_config *sc)
{
	struct azure_config	*az = sc->sc_priv;
	struct httpget		*g;
	struct xmlelem		*xe, *xv;
	int			 ret = -1;
	struct xml		 xml;

	if ((g = azure_request(sc, &xml, "/?comp=versions",
	    NULL, 0, NULL)) == NULL)
		goto done;

	if ((xe = xml_findl(&xml.ox_root,
	    "Versions", "Supported", NULL)) == NULL) {
		log_debug("%s: unexpected xml document", __func__);
		goto done;
	}

	TAILQ_FOREACH(xv, &xe->xe_head, xe_entry) {
		if (strcmp("Version", xv->xe_tag) == 0 &&
		    strcmp(xv->xe_data, az->az_apiversion) == 0) {
			/* success! */
			log_debug("%s: API version %s", __func__, xv->xe_data);
			ret = 0;
			break;
		}
	}

 done:
	xml_free(&xml);
	http_get_free(g);
	return (ret);
}

static int
azure_goalstate(struct system_config *sc)
{
	struct azure_config	*az = sc->sc_priv;
	struct httpget		*g;
	struct xmlelem		*xe;
	int			 ret = -1;
	struct xml		 xml;
	const char		*errstr = NULL;

	if ((g = azure_request(sc, &xml, "/machine/?comp=goalstate",
	    NULL, 0, NULL)) == NULL)
		goto done;

	if ((xe = xml_findl(&xml.ox_root,
	    "GoalState", "Version", NULL)) == NULL ||
	    strcmp(xe->xe_data, az->az_apiversion) != 0) {
		log_debug("%s: unexpected API version", __func__);
		goto done;
	}

	if ((xe = xml_findl(&xml.ox_root,
	    "GoalState", "Incarnation", NULL)) == NULL) {
		log_debug("%s: unexpected incarnation", __func__);
		goto done;
	}
	az->az_incarnation = strtonum(xe->xe_data, 1, INT_MAX, &errstr);
	if (errstr != NULL) {
		log_debug("%s: unexpected incarnation: %s", __func__, errstr);
		goto done;
	}

	if ((xe = xml_findl(&xml.ox_root,
	    "GoalState", "Container", "ContainerId", NULL)) == NULL ||
	    (az->az_container =
	    get_word(xe->xe_data, xe->xe_datalen)) == NULL) {
		log_debug("%s: unexpected container id", __func__);
		goto done;
	}

	if ((xe = xml_findl(&xml.ox_root,
	    "GoalState", "Container", "RoleInstanceList",
	    "RoleInstance", "InstanceId", NULL)) == NULL ||
	    (sc->sc_instance =
	    get_word(xe->xe_data, xe->xe_datalen)) == NULL) {
		log_debug("%s: unexpected instance id", __func__);
		goto done;
	}

	log_debug("%s: container %s instance %s incarnation %d", __func__,
	    az->az_container, sc->sc_instance, az->az_incarnation);

	ret = 0;
 done:
	xml_free(&xml);
	http_get_free(g);
	return (ret);
}

static int
azure_certificates(struct system_config *sc)
{
	struct azure_config	*az = sc->sc_priv;
	struct httpget		*g;
	struct httphead		*reqhead[3];
	int			 ret = -1;
	char			*req = NULL;
	char			 tmp1[32], tmp2[32];
	struct xml		 xml;
	struct xmlelem		*xe, *data;
	int			 fd;

	memset(tmp1, 0, sizeof(tmp1));
	memset(tmp2, 0, sizeof(tmp2));

	reqhead[0] = &(struct httphead){ "x-ms-cipher-name", "DES_EDE3_CBC" };
	reqhead[1] = &(struct httphead){
		"x-ms-guest-agent-public-x509-cert", az->az_pubkeyval
	};
	reqhead[2] = NULL;

	if (asprintf(&req, "/machine/%s/%s?comp=certificates&incarnation=%d",
	    az->az_container, sc->sc_instance, az->az_incarnation) == -1)
		return (-1);

	g = azure_request(sc, &xml, req, NULL, 0, reqhead);

	http_get_free(g);
	free(req);
	req = NULL;

	/* certificates are optional and only needed w/o password auth */
	if (g == NULL)
		return (0);

	if ((xe = xml_findl(&xml.ox_root,
	    "CertificateFile", "Version", NULL)) == NULL ||
	    strcmp(xe->xe_data, az->az_apiversion) != 0) {
		log_debug("%s: unexpected API version", __func__);
		goto done;
	}

	if ((xe = xml_findl(&xml.ox_root,
	    "CertificateFile", "Format", NULL)) == NULL ||
	    strcmp(xe->xe_data, "Pkcs7BlobWithPfxContents") != 0) {
		log_debug("%s: unexpected format", __func__);
		goto done;
	}

	if ((data = xml_findl(&xml.ox_root,
	    "CertificateFile", "Data", NULL)) == NULL) {
		log_debug("%s: no data", __func__);
		goto done;
	}

	/* Write CMS blob to temporary file */
	strlcpy(tmp1, "/tmp/azure-cms.XXXXXXXX", sizeof(tmp1));
	if ((fd = mkstemp(tmp1)) == -1) {
		log_debug("%s: failed to write data", __func__);
		goto done;
	}
	dprintf(fd, "MIME-Version: 1.0\n"
	    "Content-Disposition: attachment; filename=\"smime.p7m\"\n"
	    "Content-Type: application/pkcs7-mime;"
	    " smime-type=enveloped-data; name=\"smime.p7m\"\n"
	    "Content-Transfer-Encoding: base64\n"
	    "\n%s",
	    data->xe_data);
	close(fd);

	strlcpy(tmp2, "/tmp/azure-pkcs12.XXXXXXXX", sizeof(tmp2));
	if ((fd = mkstemp(tmp2)) == -1) {
		log_debug("%s: failed to write data", __func__);
		goto done;
	}
	close(fd);

	fd = disable_output(sc, STDERR_FILENO);

#ifdef USE_OPENSSL
	/*
	 * XXX Now comes the part that needs CMS which is only
	 * XXX present in OpenSSL but got removed from LibreSSL.
	 */
	log_debug("%s: running openssl cms", __func__);
	if (shell("/usr/local/bin/eopenssl", "cms", /* )) */
#else
	if (shell("/usr/local/bin/cms",
#endif
	    "-decrypt", "-inkey", az->az_privkey, "-des3",
	    "-in", tmp1, "-out", tmp2, NULL) != 0) {
		enable_output(sc, STDERR_FILENO, fd);
		log_debug("%s: failed to decrypt CMS blob", __func__);
		goto done;
	}

	unlink(tmp1);

	/* Decrypt PKCS12 blob (now with LibreSSL) */
	if (shell("openssl", "pkcs12",
	    "-nodes", "-password", "pass:",
	    "-in", tmp2, "-out", az->az_certs, NULL) != 0) {
		enable_output(sc, STDERR_FILENO, fd);
		log_debug("%s: failed to decrypt PKCS12 blob", __func__);
		goto done;
	}

	unlink(tmp2);

	enable_output(sc, STDERR_FILENO, fd);

	/*
	 * XXX the following could be done using libcrypto directly
	 */
	ret = azure_getpubkeys(sc);

 done:
	unlink(tmp1);
	unlink(tmp2);
	xml_free(&xml);

	return (ret);
}

int
azure_getpubkeys(struct system_config *sc)
{
	struct azure_config	*az = sc->sc_priv;
	char			 buf[BUFSIZ];
	char			*in = NULL, *out = NULL, *p, *v;
	FILE			*fp;
	int			 ret = -1;
	FILE			*infp = NULL;
	char			*inbuf = NULL;
	size_t			 inbufsz;

	if ((fp = fopen(az->az_certs, "r")) == NULL) {
		log_debug("%s: failed to read certificates", __func__);
		goto done;
	}

	/* Read all certificates */
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		buf[strcspn(buf, "\r\n")] = '\0';

		if (strcmp("-----BEGIN CERTIFICATE-----", buf) == 0) {
			if ((infp = open_memstream(&inbuf, &inbufsz)) == NULL) {
				log_debug("%s: failed to write cert", __func__);
				goto done;
			}
		} else if (infp == NULL)
			continue;

		fprintf(infp, "%s\n", buf);

		if (strcmp("-----END CERTIFICATE-----", buf) == 0) {
			fclose(infp);
			infp = NULL;

			/* Convert certificate into public key */
			if (shellout(inbuf, &in,
			    "openssl", "x509", "-fingerprint", "-pubkey",
			    "-noout", NULL) != 0) {
				log_debug("%s: could not get public key",
				    __func__);
				goto done;
			}

			free(inbuf);
			inbuf = NULL;

			/* Convert public key into SSH key */
			if (shellout(in, &out,
			    "ssh-keygen", "-i", "-m", "PKCS8",
			    "-f", "/dev/stdin", NULL) == -1) {
				log_debug("%s: could not get ssh key",
				    __func__);
				goto done;
			}

			/* Get public key fingerprint */
			if ((p = strstr(in, "Fingerprint=")) == NULL) {
				log_debug("%s: could not get fingerprint",
				    __func__);
				goto done;
			}
			p[strcspn(p, "\r\n")] = '\0';
			p += strlen("Fingerprint=");

			/* Strip colons */
			for (v = p + strlen(p); v != p; v--)
				if (*v == ':')
					memmove(v, v + 1, strlen(v));

			if (agent_setpubkey(sc, out, p) > 0)
				log_debug("%s: public key %s", __func__, p);

			free(in);
			in = NULL;
			free(out);
			out = NULL;
		}
	}

	ret = 0;
 done:
	free(inbuf);
	free(in);
	free(out);
	return (ret);
}

static int
azure_reporthealth(struct system_config *sc, const char *message)
{
	struct azure_config	*az = sc->sc_priv;
	struct httpget		*g = NULL;
	struct httphead		*httph, *reqhead[2];
	const char		*errstr = NULL;
	size_t			 httphsz, i;
	int			 ret = -1;
	char			*req;
	int			 reqsz;
	const char		*state;

	reqhead[0] = &(struct httphead){
		"Content-Type", "text/xml; charset=utf-8"
	};
	reqhead[1] = NULL;

	if (strcmp("Ready", message) == 0) {
		state = "<State>Ready</State>";
	} else {
		state =
"<State>NotReady</State>\n"
"<Details>\n"
  "<SubStatus>Provisioning</SubStatus>\n"
  "<Description>Starting</Description>\n"
"</Details>";
	}

	reqsz = asprintf(&req,
"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
"<Health xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\n"
  "<GoalStateIncarnation>%u</GoalStateIncarnation>\n"
  "<Container>\n"
    "<ContainerId>%s</ContainerId>\n"
    "<RoleInstanceList>\n"
      "<Role>\n"
        "<InstanceId>%s</InstanceId>\n"
        "<Health>%s</Health>\n"
      "</Role>\n"
    "</RoleInstanceList>\n"
  "</Container>\n"
"</Health>\n",
		    az->az_incarnation,
		    az->az_container,
		    sc->sc_instance,
		    state);
	if (reqsz == -1)
		goto done;

	if ((g = azure_request(sc, NULL, "/machine/?comp=health",
	    req, reqsz, reqhead)) == NULL)
		goto done;

	httph = http_head_parse(g->http, g->xfer, &httphsz);

	for (i = 0; i < httphsz; i++) {
		if (strcmp(httph[i].key,
		    "x-ms-latest-goal-state-incarnation-number") == 0) {
			az->az_incarnation =
			    strtonum(httph[i].val, 1, INT_MAX, &errstr);
			if (errstr != NULL) {
				log_debug("%s: unexpected incarnation: %s",
				    __func__, errstr);
				goto done;
			}
			ret = 0;
			break;
		}
	}

	if (ret != 0)
		goto done;

	log_debug("%s: %s, incarnation %u", __func__,
	    message, az->az_incarnation);

 done:
	http_get_free(g);
	return (ret);
}

static int
azure_getovfenv(struct system_config *sc)
{
	struct xml	 xml;
	struct xmlelem	*xp, *xe, *xk, *xv;
	char		*sshfp, *sshval, *str;
	int		 ret = -1, fd = -1;
	FILE		*fp;

	if (xml_init(&xml) != 0) {
		log_debug("%s: xml", __func__);
		goto done;
	}

	/*
	 * Assume that the cdrom is already mounted.
	 * Fallback to and older ovf-env.xml file.
	 */
	if (xml_parse(&xml, "/mnt/ovf-env.xml") == -1 &&
	    xml_parse(&xml, sc->sc_ovfenv) == -1)
		goto done;

	if ((xp = xml_findl(&xml.ox_root,
	    "Environment", "wa:ProvisioningSection",
	    "LinuxProvisioningConfigurationSet", NULL)) == NULL) {
		log_debug("%s: could not find OVF structure", __func__);
		goto done;
	}

	if ((xe = xml_findl(&xp->xe_head,
	    "SSH", "PublicKeys", NULL)) != NULL) {
		/* Find all (optional) SSH keys */
		TAILQ_FOREACH(xk, &xe->xe_head, xe_entry) {
			if (strcasecmp(xk->xe_tag, "PublicKey") != 0)
				continue;

			sshfp = sshval = NULL;

			if ((xv = xml_findl(&xk->xe_head,
			    "Fingerprint", NULL)) != NULL)
				sshfp = get_word(xv->xe_data, xv->xe_datalen);
			if ((xv = xml_findl(&xk->xe_head,
			    "Value", NULL)) != NULL)
				sshval = get_line(xv->xe_data, xv->xe_datalen);

			if (agent_addpubkey(sc, sshval, sshfp) != 0)
				log_warnx("failed to add ssh pubkey");
			free(sshfp);
			free(sshval);
		}
	}

	if ((xe = xml_findl(&xp->xe_head, "HostName", NULL)) != NULL) {
		if ((sc->sc_hostname =
		    get_word(xe->xe_data, xe->xe_datalen)) == NULL) {
			log_debug("%s: hostname failed", __func__);
			goto done;
		}
	}

	if ((xe = xml_findl(&xp->xe_head, "UserName", NULL)) != NULL) {
		free(sc->sc_username);
		if ((sc->sc_username =
		    get_word(xe->xe_data, xe->xe_datalen)) == NULL) {
			log_debug("%s: username failed", __func__);
			goto done;
		}
	}

	if ((xe = xml_findl(&xp->xe_head, "UserPassword", NULL)) != NULL) {
		if ((sc->sc_password = calloc(1, 128)) == NULL) {
			log_debug("%s: password failed", __func__);
			goto done;
		}
		/* Allow any non-NUL character as input */
		str = strndup(xe->xe_data, xe->xe_datalen);
		if (str == NULL ||
		    crypt_newhash(str, "bcrypt,a",
		    sc->sc_password, 128) != 0) {
			log_debug("%s: password hashing failed", __func__);
			free(sc->sc_password);
			sc->sc_password = NULL;
			free(str);
			goto done;
		}
		free(str);

		/* Replace unencrypted password with hash */
		free(xe->xe_tag);
		xe->xe_tag = strdup("UserPasswordHash");

		/* Update element for xml_print() below */
		explicit_bzero(xe->xe_data, xe->xe_datalen);
		free(xe->xe_data);
		xe->xe_data = strdup(sc->sc_password);
		xe->xe_datalen = strlen(sc->sc_password);
	} else if ((xe = xml_findl(&xp->xe_head,
	    "UserPasswordHash", NULL)) != NULL) {
		if ((sc->sc_password =
		    get_word(xe->xe_data, xe->xe_datalen)) != NULL) {
			log_debug("%s: password hash failed", __func__);
			goto done;
		}
	}

	if ((xe = xml_findl(&xp->xe_head, "CustomData", NULL)) != NULL) {
		if ((sc->sc_userdata =
		    get_string(xe->xe_data, xe->xe_datalen)) == NULL) {
			log_debug("%s: userdata failed", __func__);
			goto done;
		}
	}

	if ((fd = open(sc->sc_ovfenv, O_WRONLY|O_CREAT|O_TRUNC, 0600)) == -1 ||
	    (fp = fdopen(fd, "w")) == NULL) {
		log_debug("%s: failed to open %s", __func__, sc->sc_ovfenv);
		goto done;
	}

	xml_print(&xml, TAILQ_FIRST(&xml.ox_root), 0, fp);
	fclose(fp);

	log_debug("%s: wrote %s", __func__, sc->sc_ovfenv);

	ret = 0;
 done:
	if (fd != -1)
		close(fd);
	xml_free(&xml);
	return (ret);
}
