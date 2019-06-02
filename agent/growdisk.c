/*
 * Copyright (c) 2019 Reyk Floeter <reyk@openbsd.org>
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

#include <sys/param.h>	/* DEV_BSIZE */
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/dkio.h>
#define DKTYPENAMES
#include <sys/disklabel.h>

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <util.h>
#include <err.h>

#include "main.h"

static uint16_t	 dkcksum(struct disklabel *);

static uint16_t
dkcksum(struct disklabel *lp)
{
	uint16_t	*start, *end, sum;
	start = (uint16_t *)lp;
	end = (uint16_t *)&lp->d_partitions[lp->d_npartitions];
	for (sum = 0; start < end;)
		sum ^= *start++;
	return (sum);
}

int
growdisk(struct system_config *sc)
{
	char			 c, last_part = 0, *out = NULL, *path = NULL;
	int			 ret = -1, i, errfd, outfd;
	uint64_t		 bend, psize;
	struct partition	*pp, *p = NULL;
	struct disklabel	 lp;
	uint16_t		 cksum;
	int			 fd;

	/*
	 * Grow the OpenBSD MBR partition
	 */

	/* XXX this is a bit ugly but easier to do */
	if (!sc->sc_dryrun &&
	    shellout("e 3\n\n\n\n*\nw\nq\n", &out,
	    "fdisk", "-e", sc->sc_rootdisk, NULL) != 0) {
		log_warnx("failed to grow OpenBSD partition");
		return (-1);
	}
	free(out);

	/*
	 * Grow the last partition in the disklabel
	 */

	if ((fd = opendev(sc->sc_rootdisk,
	    O_RDWR, OPENDEV_PART, NULL)) == -1) {
		log_warn("failed to open %s", sc->sc_rootdisk);
		return (-1);
	}

	if (ioctl(fd, DIOCGDINFO, &lp) == -1) {
		log_warn("failed to get disklabel");
		goto done;
	}

	if (lp.d_magic != DISKMAGIC || lp.d_magic2 != DISKMAGIC) {
		log_warnx("invalid disklabel magic bytes");
		goto done;
	}
	cksum = lp.d_checksum;
	lp.d_checksum = 0;

	if (dkcksum(&lp) != cksum) {
		log_warnx("invalid disklabel checksum");
		goto done;
	}

	pp = lp.d_partitions;
	for (i = 0, pp = lp.d_partitions; i < lp.d_npartitions; i++, pp++) {
		if (!DL_GETPSIZE(pp))
			continue;
		c = 'a' + i;
		if (pp->p_fstype == FS_BSDFFS) {
			last_part = c;
			p = pp;
		}
	}

	if (last_part == 0) {
		log_warnx("last BSD partition not found");
		goto done;
	}

	bend = DL_GETDSIZE(&lp) - DL_GETBSTART(&lp);
	psize = DL_GETBEND(&lp) - DL_GETPOFFSET(p);

	if (sc->sc_dryrun ||
	    (bend == DL_GETBEND(&lp) && psize == DL_GETPSIZE(p))) {
		log_debug("%s: %s%c uses maximum size %llu",
		    __func__, sc->sc_rootdisk, last_part, psize);

		ret = 0;
		goto done;
	}

	log_debug("%s: growing %s%c from %llu to %llu",
	    __func__, sc->sc_rootdisk, last_part, DL_GETPSIZE(p), psize);

	/* Update OpenBSD boundaries */
	DL_SETBEND(&lp, bend);

	/* Update the size of the last partition */
	DL_SETPSIZE(p, psize);

	lp.d_checksum = dkcksum(&lp);

	if (ioctl(fd, DIOCWDINFO, &lp) == -1) {
		log_warn("failed to write disklabel");
		goto done;
	}

	/*
	 * Grow the filesystem
	 */

	if (asprintf(&path, "/dev/%s%c", sc->sc_rootdisk, last_part) == -1)
		goto done;

	errfd = disable_output(sc, STDERR_FILENO);
	outfd = disable_output(sc, STDOUT_FILENO);

	(void)shell("umount", "-f", path, NULL);
	(void)shell("growfs", "-yq", path, NULL);
	if ((ret = shell("fsck", "-y", path, NULL)) != 0)
		ret = -1;

	enable_output(sc, STDERR_FILENO, errfd);
	enable_output(sc, STDOUT_FILENO, outfd);

	ret = 0;
 done:
	free(path);
	close(fd);
	return (ret);
}
