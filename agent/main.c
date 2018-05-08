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

#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>

#include <limits.h>
#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <resolv.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <err.h>

#include "main.h"
#include "xml.h"

__dead void			 usage(void);
static struct system_config	*agent_init(const char *, int, int);
static int			 agent_configure(struct system_config *);
static void			 agent_free(struct system_config *);
static int			 agent_pf(struct system_config *, int);
static int			 agent_userdata(const unsigned char *, size_t);
static void			 agent_unconfigure(void);
static char			*metadata_parse(char *, size_t, enum strtype);

static int			 agent_timeout;

int
shell(const char *arg, ...)
{
	const char	**argv, *a;
	int		 argc, i = 0, status;
	va_list		 ap;
	pid_t		 pid, child_pid;
	struct sigaction sigint, sigquit;
	sigset_t	 mask, omask;

	/* create arguments */
	va_start(ap, arg);
	for (argc = 2; va_arg(ap, const char *) != NULL; argc++)
		;
	va_end(ap);

	if ((argv = calloc(argc, sizeof(const char *))) == NULL)
		fatal("%s: calloc", __func__);
	argv[i++] = arg;

	va_start(ap, arg);
	while ((a = va_arg(ap, char *)) != NULL)
		argv[i++] = a;
	va_end(ap);

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &mask, &omask);

	/* run command in forked process */
	switch (child_pid = fork()) {
	case -1:
		sigprocmask(SIG_SETMASK, &omask, NULL);
		free(argv);
		return (-1);
	case 0:
		sigprocmask(SIG_SETMASK, &omask, NULL);
		execvp(argv[0], (char *const *)(caddr_t)argv);
		_exit(127);
	}

	free(argv);
	sigaction(SIGINT, NULL, &sigint);
	sigaction(SIGQUIT, NULL, &sigquit);

	do {
		pid = waitpid(child_pid, &status, 0);
	} while (pid == -1 && errno == EINTR);

	sigprocmask(SIG_SETMASK, &omask, NULL);
	sigaction(SIGINT, &sigint, NULL);
	sigaction(SIGQUIT, &sigquit, NULL);

	/* Simplified return value: returns 0 on success and -1 on error */
	if (pid != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return (0);

	return (-1);
}

int
shellout(const char *in, char **out, const char *arg, ...)
{
	const char	**argv = NULL, *a;
	int		 argc, i = 0, status;
	va_list		 ap;
	pid_t		 pid, child_pid;
	struct sigaction sigint, sigquit;
	sigset_t	 mask, omask;
	FILE		*outfp = NULL, *fp = NULL;
	char		*outbuf;
	size_t		 outbufsz;
	char		 buf[BUFSIZ];
	int		 fdi[2], fdo[2];

	if (out)
		*out = NULL;

	/* create arguments */
	va_start(ap, arg);
	for (argc = 2; va_arg(ap, const char *) != NULL; argc++)
		;
	va_end(ap);

	if ((argv = calloc(argc, sizeof(const char *))) == NULL)
		fatal("%s: calloc", __func__);
	argv[i++] = arg;

	va_start(ap, arg);
	while ((a = va_arg(ap, char *)) != NULL)
		argv[i++] = a;
	va_end(ap);

	if (in && socketpair(AF_UNIX,
	    SOCK_STREAM|SOCK_CLOEXEC, AF_UNSPEC, fdi) == -1)
		goto fail;

	if (out && socketpair(AF_UNIX,
	    SOCK_STREAM|SOCK_CLOEXEC, AF_UNSPEC, fdo) == -1)
		goto fail;

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &mask, &omask);

	/* run command in forked process */
	switch (child_pid = fork()) {
	case -1:
		sigprocmask(SIG_SETMASK, &omask, NULL);
		goto fail;
	case 0:
		if (in) {
			close(fdi[1]);
			if (dup2(fdi[0], STDIN_FILENO) == -1)
				_exit(127);
		}
		if (out) {
			close(fdo[1]);
			if (dup2(fdo[0], STDOUT_FILENO) == -1)
				_exit(127);
		}
		sigprocmask(SIG_SETMASK, &omask, NULL);
		execvp(argv[0], (char *const *)(caddr_t)argv);
		_exit(127);
	}

	free(argv);
	argv = NULL;
	sigaction(SIGINT, NULL, &sigint);
	sigaction(SIGQUIT, NULL, &sigquit);

	if (in) {
		close(fdi[0]);
		if ((fp = fdopen(fdi[1], "w")) != NULL) {
			fputs(in, fp);
			fflush(fp);
			fclose(fp);
		}
		close(fdi[1]);
	}

	if (out) {
		close(fdo[0]);
		if ((fp = fdopen(fdo[1], "r")) != NULL &&
		    (outfp = open_memstream(&outbuf, &outbufsz)) != NULL) {
			while (fgets(buf, sizeof(buf), fp) != NULL) {
				fputs(buf, outfp);
			}
			fclose(outfp);
			*out = outbuf;
		}
		fclose(fp);
		close(fdo[1]);
	}

	do {
		pid = waitpid(child_pid, &status, 0);
	} while (pid == -1 && errno == EINTR);

	sigprocmask(SIG_SETMASK, &omask, NULL);
	sigaction(SIGINT, &sigint, NULL);
	sigaction(SIGQUIT, &sigquit, NULL);

	/* Simplified return value: returns 0 on success and -1 on error */
	if (pid != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return (0);

 fail:
	free(argv);
	if (out) {
		free(*out);
		*out = NULL;
	}
	return (-1);
}

int
disable_output(struct system_config *sc, int fd)
{
	int	 oldfd;

	if (log_getverbose() > 2)
		return (-1);

	if ((oldfd = dup(fd)) == -1 ||
	    dup2(sc->sc_nullfd, fd) == -1)
		return (-1);

	return (oldfd);
}

int
enable_output(struct system_config *sc, int fd, int oldfd)
{
	if (oldfd == -1)
		return (0);

	close(fd);
	if (dup2(oldfd, fd) == -1)
		return (-1);

	return (0);
}

char *
get_string(const unsigned char *ptr, size_t len)
{
	size_t	 i;

	/*
	 * We don't use vis(3) here because the string should not be
	 * modified and only validated for printable characters and proper
	 * NUL-termination.  From relayd.
	 */
	for (i = 0; i < len; i++)
		if (!(isprint((unsigned char)ptr[i]) ||
		    isspace((unsigned char)ptr[i])))
			break;

	return strndup(ptr, i);
}

char *
get_line(const unsigned char *ptr, size_t len)
{
	size_t	 i;

	/* Like the previous, but without newlines */
	for (i = 0; i < len; i++)
		if (!isprint((unsigned char)ptr[i]) ||
		    (isspace((unsigned char)ptr[i]) &&
		    !isblank((unsigned char)ptr[i])))
			break;

	return strndup(ptr, i);
}

char *
get_word(const unsigned char *ptr, size_t len)
{
	size_t	 i;

	/* Like the previous, but without spaces and newlines */
	for (i = 0; i < len; i++)
		if (!isprint((unsigned char)ptr[i]) ||
		    isspace((unsigned char)ptr[i]))
			break;

	return strndup(ptr, i);
}

static struct system_config *
agent_init(const char *ifname, int dryrun, int timeout)
{
	struct system_config	*sc;

	if ((sc = calloc(1, sizeof(*sc))) == NULL)
		return (NULL);

	sc->sc_interface = ifname;
	sc->sc_dryrun = dryrun ? 1 : 0;
	sc->sc_timeout = agent_timeout = timeout < 1 ? -1 : timeout * 1000;
	TAILQ_INIT(&sc->sc_pubkeys);

	if ((sc->sc_nullfd = open("/dev/null", O_RDWR)) == -1) {
		free(sc);
		return (NULL);
	}
	if ((sc->sc_username = strdup("puffy")) == NULL) {
		free(sc);
		close(sc->sc_nullfd);
		return (NULL);
	}

	if (sc->sc_dryrun)
		return (sc);

	if (agent_pf(sc, 1) != 0)
		fatalx("pf");
	if (http_init() == -1)
		fatalx("http_init");

	return (sc);
}

static void
agent_free(struct system_config *sc)
{
	struct ssh_pubkey	*ssh;

	free(sc->sc_hostname);
	free(sc->sc_username);
	free(sc->sc_password);
	free(sc->sc_userdata);
	free(sc->sc_endpoint);
	free(sc->sc_instance);
	close(sc->sc_nullfd);

	while ((ssh = TAILQ_FIRST(&sc->sc_pubkeys))) {
		free(ssh->ssh_keyval);
		free(ssh->ssh_keyfp);
		TAILQ_REMOVE(&sc->sc_pubkeys, ssh, ssh_entry);
		free(ssh);
	}
}

int
agent_addpubkey(struct system_config *sc, const char *sshval, const char *sshfp)
{
	struct ssh_pubkey	*ssh;

	/* Ignore if neither key nor fingerprint is available */
	if (sshval == NULL && sshfp == NULL)
		return (0);

	if ((ssh = calloc(1, sizeof(*ssh))) == NULL)
		return (-1);

	if (sshfp != NULL && (ssh->ssh_keyfp = strdup(sshfp)) == NULL) {
		free(ssh);
		return (-1);
	}

	if (sshval != NULL && (ssh->ssh_keyval = strdup(sshval)) == NULL) {
		free(ssh->ssh_keyfp);
		free(ssh);
		return (-1);
	}

	TAILQ_INSERT_TAIL(&sc->sc_pubkeys, ssh, ssh_entry);

	return (0);
}

int
agent_setpubkey(struct system_config *sc, const char *sshval, const char *sshfp)
{
	struct ssh_pubkey	*ssh;
	int			 ret = 0;
	char			*v = NULL;

	TAILQ_FOREACH(ssh, &sc->sc_pubkeys, ssh_entry) {
		if (sshfp && ssh->ssh_keyfp &&
		    strcasecmp(ssh->ssh_keyfp, sshfp) == 0) {
			if ((sshval == NULL) ||
			    (sshval && (v = strdup(sshval)) == NULL))
				break;
			v[strcspn(v, "\r\n")] = '\0';
			free(ssh->ssh_keyval);
			ssh->ssh_keyval = v;
			ret++;
		}
	}

	return (ret);
}

static int
fileout(const char *str, const char *mode, const char *fmt, ...)
{
	FILE	*fp;
	va_list	 ap;
	char	*path;
	int	 ret;

	va_start(ap, fmt);
	ret = vasprintf(&path, fmt, ap);
	va_end(ap);

	if (ret == -1)
		return (-1);
	if ((fp = fopen(path, mode)) == NULL) {
		free(path);
		return (-1);
	}
	if (str != NULL) {
		fputs(str, fp);
		if (strpbrk(str, "\r\n") == NULL)
			fputs("\n", fp);
	}
	fclose(fp);

	free(path);

	return (0);
}

static char *
filein(const char *mode, const char *fmt, ...)
{
	FILE	*fp;
	va_list	 ap;
	char	*path;
	int	 ret;
	char	 buf[BUFSIZ];
	FILE	*infp;
	char	*inbuf;
	size_t	 inbufsz;

	va_start(ap, fmt);
	ret = vasprintf(&path, fmt, ap);
	va_end(ap);

	if (ret == -1)
		return (NULL);
	if ((fp = fopen(path, mode)) == NULL) {
		free(path);
		return (NULL);
	}
	free(path);
	if ((infp = open_memstream(&inbuf, &inbufsz)) == NULL) {
		fclose(fp);
		return (NULL);
	}
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		fputs(buf, infp);
	}
	fclose(fp);
	fclose(infp);

	return (inbuf);
}

static int
agent_pf(struct system_config *sc, int open)
{
	int	 ret;

	if (shell("rcctl", "get", "pf", "status", NULL) != 0)
		return (0);

	if (open)
		ret = shellout("pass out proto tcp from egress to port www\n",
		    NULL, "pfctl", "-f", "-", NULL);
	else
		ret = shellout("\n", NULL, "pfctl", "-f", "-", NULL);

	return (ret);
}

static int
agent_configure(struct system_config *sc)
{
	struct ssh_pubkey	*ssh;
	char			*str1, *str2;

	/* Skip configuration on the same instance */
	if ((str1 = filein("r", "/var/db/cloud-instance")) != NULL) {
		str1[strcspn(str1, "\r\n")] = '\0';
		if (strcmp(sc->sc_instance, str1) == 0) {
			free(str1);
			return (0);
		}
	}
	free(str1);

	if (fileout(sc->sc_instance, "w", "/var/db/cloud-instance") != 0)
		log_warnx("instance failed");

	/* hostname */
	log_debug("%s: hostname %s", __func__, sc->sc_hostname);
	if (fileout(sc->sc_hostname, "w", "/etc/myname") != 0)
		log_warnx("hostname failed");
	else
		(void)shell("hostname", sc->sc_hostname, NULL);

	/* username */
	log_debug("%s: username %s", __func__, sc->sc_username);
	if (shell("useradd", "-L", "staff", "-G", "wheel",
	    "-m", sc->sc_username, NULL) != 0)
		log_warnx("username failed");
	if (fileout(sc->sc_username, "w", "/root/.forward") != 0)
		log_warnx(".forward failed");

	/* password */
	if (sc->sc_password == NULL) {
		str1 = "/PasswordAuthentication/"
		    "s/.*/PasswordAuthentication no/";
		if (asprintf(&str2, "permit keepenv nopass %s as root\n"
		    "permit keepenv nopass root\n", sc->sc_username) == -1)
			str2 = NULL;
	} else {
		if (shell("usermod", "-p", sc->sc_password,
		    sc->sc_username, NULL) != 0)
			log_warnx("password failed");

		str1 = "/PasswordAuthentication/"
		    "s/.*/PasswordAuthentication yes/";
		if (asprintf(&str2, "permit keepenv persist %s as root\n"
		    "permit keepenv nopass root\n", sc->sc_username) == -1)
			str2 = NULL;
	}

	/* doas */
	if (str2 == NULL || fileout(str2, "w", "/etc/doas.conf") != 0)
		log_warnx("doas failed");
	free(str2);

	/* ssh configuration */
	if (sc->sc_password == NULL && !TAILQ_EMPTY(&sc->sc_pubkeys))
		str1 = "/PasswordAuthentication/"
		    "s/.*/PasswordAuthentication no/";
	else
		str1 = "/PasswordAuthentication/"
		    "s/.*/PasswordAuthentication yes/";
	shell("sed", "-i", "-e", str1,
	    "-e", "/ClientAliveInterval/s/.*/ClientAliveInterval 180/",
	    "/etc/ssh/sshd_config",
	    NULL);

	/* ssh public keys */
	TAILQ_FOREACH(ssh, &sc->sc_pubkeys, ssh_entry) {
		if (ssh->ssh_keyval == NULL)
			continue;
		log_debug("%s: key %s", __func__, ssh->ssh_keyval);
		if (fileout(ssh->ssh_keyval, "a",
		    "/home/%s/.ssh/authorized_keys",
		    sc->sc_username) != 0)
			log_warnx("public key failed");
	}

	if (sc->sc_userdata) {
		if (agent_userdata(sc->sc_userdata,
		    strlen(sc->sc_userdata)) != 0)
			log_warnx("user-data failed");
	}

	log_debug("%s: %s", __func__, "/etc/rc.firsttime");
	if (fileout("logger -s -t cloud-agent <<EOF\n"
	    "#############################################################\n"
	    "-----BEGIN SSH HOST KEY FINGERPRINTS-----\n"
	    "$(for _f in /etc/ssh/ssh_host_*_key.pub;"
	    " do ssh-keygen -lf ${_f}; done)\n"
	    "-----END SSH HOST KEY FINGERPRINTS-----\n"
	    "#############################################################\n"
	    "EOF\n",
	    "a", "/etc/rc.firsttime") != 0)
		log_warnx("ssh fingerprints failed");

	return (0);
}

static int
agent_userdata(const unsigned char *userdata, size_t len)
{
	char		*shebang = NULL, *str = NULL, *line = NULL;
	const char	*file;
	int		 ret = -1;

	if (len <= 2) {
		log_warnx("user-data too short");
		goto fail;
	}

	if (userdata[0] == 0x1f && userdata[1] == 0x8b) {
		log_warnx("gzip-compressed user-data is not supported");
		goto fail;
	} else if (userdata[0] == '#') {
		if ((shebang = get_line(userdata, len)) == NULL) {
			log_warnx("failed to decode shebang from user-data");
			goto fail;
		}
	} else if (isprint(userdata[0]) && isprint(userdata[1])) {
		/* Decode user-data and call the function again */
		if ((str = calloc(1, len + 1)) == NULL ||
		    (len = b64_pton(userdata, str, len)) < 1 ||
		    agent_userdata(str, len) != 0) {
			log_warnx("failed to decode user-data");
			goto fail;
		}
		goto done;
	}

	log_debug("%s: user-data: %s", __func__, shebang);

	if (strlen(shebang) <= 2 || strncmp("#!", shebang, 2) != 0) {
		log_warnx("unsupported user-data type");
		goto fail;
	}

	/* now get the whole script */
	if ((str = get_string(userdata, len)) == NULL) {
		log_warnx("invalid user-data script");
		goto fail;
	}

	/* write user-data script into file */
	file = "/etc/rc.user-data";
	if (fileout(str, "w", file) != 0) {
		log_warnx("failed to write user-data");
		goto fail;
	}

	/* and call it from rc.firsttime later on boot */
	if (asprintf(&line,
	    "logger -s -t cloud-agent \"running user-data\"\n"
	    "%s %s\nrm %s\n", shebang + 2, file, file) == -1 ||
	    fileout(line, "a", "/etc/rc.firsttime") != 0)
		log_warnx("failed to add user-data script");

 done:
	ret = 0;
 fail:
	free(line);
	free(str);
	free(shebang);

	return (ret);
}

void
agent_unconfigure(void)
{
	/* Disable root pasword */
	(void)shell("chpass", "-a",
	    "root:*:0:0:daemon:0:0:Charlie &:/root:/bin/ksh", NULL);

	/* Delete keys */
	(void)shell("sh", "-c",
	    "rm -rf /etc/{iked,isakmpd}/{local.pub,private/local.key}"
	    " /etc/ssh/ssh_host_*"
	    " /etc/dhclient.conf /var/db/dhclient.leases.*"
	    " /tmp/{.[!.],}*", NULL);

	/* Delete old seed files */
	(void)fileout(NULL, "w", "/etc/random.seed");
	(void)fileout(NULL, "w", "/var/db/host.random");

	/* Clear logfiles */
	(void)shell("sh", "-c",
	    "for _l in $(find /var/log -type f ! -name '*.gz' -size +0); do"
	    " >${_l}; "
	    "done", NULL);

	(void)fileout("permit keepenv persist :wheel as root\n"
	    "permit keepenv nopass root\n", "w", "/etc/doas.conf");
}


static char *
metadata_parse(char *s, size_t sz, enum strtype type)
{
	char	*str;

	switch (type) {
	case TEXT:
		/* multi-line string, always printable */
		str = get_string(s, sz);
		break;
	case LINE:
		str = get_line(s, sz);
		break;
	case WORD:
		str = get_word(s, sz);
		break;
	}

	return (str);
}

char *
metadata(struct system_config *sc, const char *path, enum strtype type)
{
	struct httpget	*g = NULL;
	char		*str = NULL;

	g = http_get(&sc->sc_addr, 1,
	    sc->sc_endpoint, 80, path, NULL, 0, NULL);
	if (g != NULL)
		log_debug("%s: HTTP %d %s", __func__, g->code, path);

	if (g != NULL && g->code == 200 && g->bodypartsz > 0)
		str = metadata_parse(g->bodypart, g->bodypartsz, type);
	http_get_free(g);

	return (str);
}

char *
metadata_file(struct system_config *sc, const char *name, enum strtype type)
{
	FILE		*fp, *mfp;
	char		 buf[BUFSIZ], *mbuf, *str;
	size_t		 sz, msz;

	if ((fp = fopen(name, "r")) == NULL) {
		log_warn("%s: could not open %s", __func__, name);
		return (NULL);
	}

	if ((mfp = open_memstream(&mbuf, &msz)) == NULL) {
		log_warn("%s: open_memstream", __func__);
		fclose(fp);
		return (NULL);
	}

	do {
		if ((sz = fread(buf, 1, sizeof(buf), fp)) < 1)
			break;
		if (fwrite(buf, sz, 1, mfp) != 1)
			break;
	} while (sz == sizeof(buf));

	fclose(mfp);
	fclose(fp);

	str = metadata_parse(mbuf, msz, type);
	free(mbuf);

	return (str);
}

int
connect_wait(int s, const struct sockaddr *name, socklen_t namelen)
{
	struct pollfd	 pfd[1];
	int		 error = 0, flag;
	socklen_t	 errlen = sizeof(error);

	if ((flag = fcntl(s, F_GETFL, 0)) == -1 ||
	    (fcntl(s, F_SETFL, flag | O_NONBLOCK)) == -1)
		return (-1);

	error = connect(s, name, namelen);
	do {
		pfd[0].fd = s;
		pfd[0].events = POLLOUT;

		if ((error = poll(pfd, 1, agent_timeout)) == -1)
			continue;
		if (error == 0) {
			error = ETIMEDOUT;
			goto done;
		}
		if (getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &errlen) == -1)
			continue;
	} while (error != 0 && error == EINTR);

 done:
	if (fcntl(s, F_SETFL, flag & ~O_NONBLOCK) == -1)
		return (-1);

	if (error != 0) {
		errno = error;
		return (-1);
	}

	return (0);
}

int
dhcp_getendpoint(struct system_config *sc)
{
	char	 path[PATH_MAX], buf[BUFSIZ], *ep = NULL;
	int	 a[4], has245 = 0;
	size_t	 sz;
	FILE	*fp;

	if ((size_t)snprintf(path, sizeof(path), "/var/db/dhclient.leases.%s",
	    sc->sc_interface) >= sizeof(path)) {
		log_debug("%s: invalid path", __func__);
		return (-1);
	}

	if ((fp = fopen(path, "r")) == NULL) {
		log_debug("%s: failed to open %s", __func__, path);
		return (-1);
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		buf[strcspn(buf, ";\n")] = '\0';

		/* Find last occurence of dhcp-server-identifier */
		sz = strlen("  option dhcp-server-identifier ");
		if (!has245 &&
		    strncmp(buf, "  option dhcp-server-identifier ", sz) == 0) {
			free(ep);
			if ((ep = strdup(buf + sz)) == NULL) {
				log_debug("%s: strdup", __func__);
				fclose(fp);
				return (-1);
			}
		}

		/* Find last occurence of option-245 (only on Azure) */
		if (sscanf(buf, "  option option-245 %x:%x:%x:%x",
		    &a[0], &a[1], &a[2], &a[3]) == 4) {
			has245 = 1;
			free(ep);
			if (asprintf(&ep, "%d.%d.%d.%d",
			    a[0], a[1], a[2], a[3]) == -1) {
				log_debug("%s: asprintf", __func__);
				fclose(fp);
				return (-1);
			}
		}
	}

	fclose(fp);

	if (ep == NULL)
		return (-1);

	sc->sc_endpoint = ep;
	sc->sc_addr.ip = sc->sc_endpoint;
	sc->sc_addr.family = 4;

	log_debug("%s: %s", __func__, ep);

	return (0);
}

__dead void
usage(void)
{
	extern char	*__progname;

	fprintf(stderr, "usage: %s [-nuv] [-t 3] interface\n",
	    __progname);
	exit(1);
}

int
main(int argc, char *const *argv)
{
	struct system_config	*sc;
	int			 verbose = 0, dryrun = 0, unconfigure = 0;
	int			 ch, ret, timeout = CONNECT_TIMEOUT;
	const char		*error = NULL;

	while ((ch = getopt(argc, argv, "nvt:u")) != -1) {
		switch (ch) {
		case 'n':
			dryrun = 1;
			break;
		case 'v':
			verbose += 2;
			break;
		case 't':
			timeout = strtonum(optarg, -1, 86400, &error);
			if (error != NULL)
				fatalx("invalid timeout: %s", error);
			break;
		case 'u':
			unconfigure = 1;
			break;
		default:
			usage();
		}
	}

	argv += optind;
	argc -= optind;

	/* log to stderr */
	log_init(1, LOG_DAEMON);
	log_setverbose(verbose);

	if (unconfigure) {
		agent_unconfigure();
		exit(0);
	}

	if (argc != 1)
		usage();

	if (pledge("stdio cpath rpath wpath exec proc dns inet", NULL) == -1)
		fatal("pledge");

	if ((sc = agent_init(argv[0], dryrun, timeout)) == NULL)
		fatalx("agent");

	/*
	 * XXX Detect cloud with help from hostctl and sysctl
	 * XXX in addition to the interface name.
	 */
	if (strcmp("hvn0", sc->sc_interface) == 0)
		ret = azure(sc);
	else if (strcmp("xnf0", sc->sc_interface) == 0)
		ret = ec2(sc);
	else
		ret = openstack(sc);

	if (sc->sc_dryrun) {
		agent_free(sc);
		return (0);
	}

	if (agent_pf(sc, 0) != 0)
		fatalx("pf");

	if (pledge("stdio cpath rpath wpath exec proc", NULL) == -1)
		fatal("pledge");

	if (ret == 0 && agent_configure(sc) != 0)
		fatal("provisioning failed");

	agent_free(sc);

	return (0);
}
