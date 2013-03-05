/*
 * $Id: ad_sendfile.c,v 1.11 2010-01-21 14:14:49 didg Exp $
 *
 * Copyright (c) 1999 Adrian Sun (asun@zoology.washington.edu)
 * All rights reserved. See COPYRIGHT.
 *
 * NOTE: the following uses the fact that sendfile() only exists on
 * machines with SA_RESTART behaviour. this is all very machine specific. 
 *
 * sendfile chainsaw from samba.
 Unix SMB/Netbios implementation.
 Version 2.2.x / 3.0.x
 sendfile implementations.
 Copyright (C) Jeremy Allison 2002.
 
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#ifdef WITH_SENDFILE

#include <atalk/adouble.h>

#include <stdio.h>

#include <sys/socket.h>
#include <sys/uio.h>

#include <errno.h>  

#include <atalk/logger.h>
#include "ad_private.h"

#if defined(SENDFILE_FLAVOR_LINUX)
#include <sys/sendfile.h>

#ifdef MY_ABC_HERE
#include <sys/syscall.h>
#endif

ssize_t sys_sendfile(int tofd, int fromfd, off_t *offset, size_t count)
#ifdef MY_ABC_HERE
{
	size_t  total = 0;

	setnonblock(tofd, 0);

	total = count;
	while (total) {
		ssize_t  nwritten;
		do {
#if !(__WORDSIZE == 64) && defined(__USE_FILE_OFFSET64)
			/*
			 * sendfile64 accepts 64-bit file pointer offset,
			 * but still use 32-bit size parameter,
			 * so larger file still need to be segmented
			 */
			size_t  ulSegment = 0x40000000; /* 1GB per segment */
			if (ulSegment > total) {
				ulSegment = total;
			}
			/* directly syscall to avoid glibc */
			nwritten = syscall(__NR_sendfile64, tofd, fromfd, offset, ulSegment);
#if 0
			if (ulSegment == total && nwritten != ulSegment) {
				syslog(LOG_ERR, "errno=%ld", errno);
			}
#endif
#else
			nwritten = sendfile(tofd, fromfd, offset, total);
#endif /* defined(__USE_FILE_OFFSET64) */
		} while (nwritten == -1 && errno == EINTR);
		if (nwritten == -1) {
			count = -1;
			goto Err;
		}
		if (nwritten == 0) {
			count = -1;
			goto Err;/* I think we're at EOF here... */
		}
		total -= nwritten;
	}
Err:
	setnonblock(tofd, 1);
	return count;
}
#else
{
    return sendfile(tofd, fromfd, offset, count);
}
#endif

#elif defined(SENDFILE_FLAVOR_SOLARIS)
#include <sys/sendfile.h>

ssize_t sys_sendfile(int tofd, int fromfd, off_t *offset, size_t count)
{
    return sendfile(tofd, fromfd, offset, count);
}

#elif defined(SENDFILE_FLAVOR_BSD )
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
ssize_t sys_sendfile(int tofd, int fromfd, off_t *offset, size_t count)
{
    off_t len;
    int ret;

    ret = sendfile(fromfd, tofd, *offset, count, NULL, &len, 0);

    *offset += len;

    if (ret != 0)
        return -1;
    return len;
}

#else

ssize_t sys_sendfile(int out_fd, int in_fd, off_t *_offset, size_t count)
{
    /* No sendfile syscall. */
    errno = ENOSYS;
    return -1;
}
#endif

/* ------------------------------- */
int ad_readfile_init(const struct adouble *ad, 
				       const int eid, off_t *off,
				       const int end)
{
  int fd;

  if (end) 
    *off = ad_size(ad, eid) - *off;

  if (eid == ADEID_DFORK) {
    fd = ad_data_fileno(ad);
  } else {
#ifdef MY_ABC_HERE
    *off += ad_getentryoff_hfs(ad, eid);
#else
    *off += ad_getentryoff(ad, eid);
#endif
    fd = ad_reso_fileno(ad);
  }

  return fd;
}


/* ------------------------ */
#ifdef MY_ABC_HERE
#include <asm/unistd.h>
#include <signal.h>

int ad_writefile_init(const struct adouble *ad,
				       const int eid, off_t *off,
				       const int end)
{
    int fd;

    if (end)
        *off = ad_size(ad, eid) - *off;

    if (eid == ADEID_DFORK) {
        fd = ad_data_fileno(ad);
    } else {
#ifdef MY_ABC_HERE
        *off += ad_getentryoff_hfs(ad, eid);
#else
        *off += ad_getentryoff(ad, eid);
#endif
        fd = ad_reso_fileno(ad);
    }

    return fd;
}

/* This function is copied from samba. */
size_t sys_recvfile(int fromfd,
			int tofd,
			off_t offset,
			size_t count)
{
	size_t rwbytes[2];
	size_t total_written = 0;
	size_t total_receive = 0;
	int      retRecv = 0;
	sigset_t set, old_set;

	bzero(rwbytes,sizeof(rwbytes));

	do {
		retRecv = 0;

		/**
		* We try to block all signals except for SIGQUIT,
		* SIGABRT, SIGKILL, SIGTERM, SIGSTOP to prevent from
		* broken pipe.
		*/
		sigfillset(&set);
		sigdelset(&set, SIGQUIT);
		sigdelset(&set, SIGABRT);
		sigdelset(&set, SIGKILL);
		sigdelset(&set, SIGTERM);
		sigdelset(&set, SIGSTOP);
		sigprocmask(SIG_BLOCK, &set, &old_set);

		retRecv = recvfile(tofd, fromfd, &offset, count-total_receive, rwbytes);
		sigprocmask(SIG_SETMASK, &old_set, NULL);
		total_receive += rwbytes[0];
		total_written += rwbytes[1];

		if ( 0 < retRecv ) {
			if (total_receive == count) {
				break;
			}
			continue;
		} else if ( 0 == retRecv ) {
			LOG(log_debug, logtype_afpd, "No data received, count=[%lu] total_received/written=[%lu/%lu] rwbytes=[%lu/%lu]",
				(unsigned long)count,
				(unsigned long)total_receive,
				(unsigned long)total_written,
				(unsigned long)rwbytes[0],
				(unsigned long)rwbytes[1]);
			break;
		}

		if ( errno == EINTR ) {
			continue;
		}
		switch(errno) {
			case EINTR:
				continue;
			case ENOSPC:
			case EDQUOT:
				SYSLOG(LOG_ERR, "%m");
				break;
			case EPIPE:
			default:
				SYSLOG(LOG_ERR, "recvfile failed (ret = -1), count=[%lu] total_received/written=[%lu/%lu] rwbytes=[%lu/%lu] errno=[%d(%m)]", 
					(unsigned long)count,
					(unsigned long)total_receive,
					(unsigned long)total_written,
					(unsigned long)rwbytes[0],
					(unsigned long)rwbytes[1],
					errno);
				break;
		}
		break;
	} while ( total_written < count );

	return total_written;
}

/* read from a socket and write to an adouble file */
ssize_t ad_writefile(struct adouble *ad, const int eid, 
		     const int sock, off_t off, const int end,
		     const size_t len)
{
#ifdef __linux__
    ssize_t cc;
    int fd;

    fd = ad_writefile_init(ad, eid, &off, end);
    if ((cc = sys_recvfile(sock, fd, off, len)) != len)
        return cc;

    if ((eid != ADEID_DFORK) && (off > ad_getentrylen(ad, eid)))
        ad_setentrylen(ad, eid, off);

    return cc;
#endif /* __linux__ */
}
#endif /* MY_ABC_HERE */
#endif
