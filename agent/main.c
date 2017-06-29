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

#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "main.h"
#include "xml.h"

__dead void			 usage(void);
static struct system_config	*agent_init(void);
static void			 agent_free(struct system_config *);
static int			 agent_pf(struct system_config *, int);
static void			 agent_unconfigure(void);

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

static struct system_config *
agent_init(void)
{
	struct system_config	*sc;

	if ((sc = calloc(1, sizeof(*sc))) == NULL)
		return (NULL);

	TAILQ_INIT(&sc->sc_pubkeys);

	if ((sc->sc_nullfd = open("/dev/null", O_RDWR)) == -1) {
		free(sc);
		return (NULL);
	}

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

int
agent_configure(struct system_config *sc, int noaction)
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

	if (!noaction &&
	    fileout(sc->sc_instance, "w", "/var/db/cloud-instance") != 0)
		log_warnx("instance failed");

	/* hostname */
	log_debug("%s: hostname %s", __func__, sc->sc_hostname);
	if (!noaction &&
	    fileout(sc->sc_hostname, "w", "/etc/myname") != 0)
		log_warnx("hostname failed");
	else
		(void)shell("hostname", sc->sc_hostname, NULL);

	/* username */
	log_debug("%s: username %s", __func__, sc->sc_username);
	if (!noaction &&
	    shell("useradd", "-L", "staff", "-G", "wheel",
	    "-m", sc->sc_username, NULL) != 0)
		log_warnx("username failed");

	/* password */
	if (sc->sc_password == NULL) {
		str1 = "/PasswordAuthentication/"
		    "s/.*/PasswordAuthentication no/";
		str2 = "permit keepenv nopass :wheel as root\n"
		    "permit keepenv nopass root\n";
	} else {
		if (!noaction &&
		    shell("usermod", "-p", sc->sc_password,
		    sc->sc_username, NULL) != 0)
			log_warnx("password failed");

		str1 = "/PasswordAuthentication/"
		    "s/.*/PasswordAuthentication yes/";
		str2 = "permit keepenv persist :wheel as root\n"
		    "permit keepenv nopass root\n";
	}

	/* doas */
	if (fileout(str2, "w", "/etc/doas.conf") != 0)
		log_warnx("doas failed");

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
		if (!noaction &&
		    fileout(ssh->ssh_keyval, "a",
		    "/home/%s/.ssh/authorized_keys",
		    sc->sc_username) != 0)
			log_warnx("public key failed");
	}

	if (sc->sc_userdata) {
		/* XXX */
	}

	log_debug("%s: %s", __func__, "/etc/rc.firsttime");
	if (!noaction && fileout("logger -s -t cloud-agent <<EOF\n"
	    "#############################################################\n"
	    "-----BEGIN SSH HOST KEY FINGERPRINTS-----\n"
	    "$(for _f in /etc/ssh/ssh_host_*_key.pub;"
	    " do ssh-keygen -lf ${_f}; done)\n"
	    "-----END SSH HOST KEY FINGERPRINTS-----\n"
	    "#############################################################\n"
	    "EOF\n",
	    "a", "/etc/rc.firsttime") != 0)
		log_warnx("userdata failed");

	return (0);
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

__dead void
usage(void)
{
	extern char	*__progname;

	fprintf(stderr, "usage: %s [-nuv] interface\n",
	    __progname);
	exit(1);
}

int
main(int argc, char *const *argv)
{
	struct system_config	*sc;
	int			 verbose = 0, noaction = 0, unconfigure = 0;
	int			 ch, ret;

	while ((ch = getopt(argc, argv, "nvu")) != -1) {
		switch (ch) {
		case 'n':
			noaction = 1;
			break;
		case 'v':
			verbose += 2;
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

	if ((sc = agent_init()) == NULL)
		fatalx("agent");

	sc->sc_interface = argv[0];

	if (agent_pf(sc, 1) != 0)
		fatalx("pf");

	if (http_init() == -1)
		fatalx("http_init");

	/*
	 * XXX Detect cloud with help from hostctl and sysctl
	 * XXX in addition to the interface name.
	 */
	if (strcmp("hvn0", sc->sc_interface) == 0)
		ret = azure(sc);
	else if (strcmp("xnf0", sc->sc_interface) == 0)
		ret = ec2(sc);
	else if (strcmp("vio0", sc->sc_interface) == 0)
		ret = cloudinit(sc);
	else
		fatal("unsupported cloud interface %s", sc->sc_interface);

	if (agent_pf(sc, 0) != 0)
		fatalx("pf");

	if (pledge("stdio cpath rpath wpath exec proc", NULL) == -1)
		fatal("pledge");

	if (ret == 0 && agent_configure(sc, noaction) != 0)
		fatal("provisioning failed");

	agent_free(sc);

	return (0);
}
