/* 
   $Id: cmd_dbd.c,v 1.6 2009-09-03 08:35:15 franklahm Exp $

   Copyright (c) 2009 Frank Lahm <franklahm@gmail.com>
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
*/

/*
  dbd specs and implementation progress
  =====================================

  St := Status

  Force option
  ------------
  
  St Spec
  -- ----
  OK If -f is requested, ensure -e is too.
     Check if volumes is using AFPVOL_CACHE, then wipe db from disk. Rebuild from ad-files.

  1st pass: Scan volume
  --------------------

  St Type Check
  -- ---- -----
  OK F/D  Make sure ad file exists
  OK D    Make sure .AppleDouble dir exist, create if missing. Error creating
          it is fatal as that shouldn't happen as root.
  OK F/D  Delete orphaned ad-files, log dirs in ad-dir
  OK F/D  Check name encoding by roundtripping, log on error
  OK F/D  try: read CNID from ad file (if cnid caching is on)
          try: fetch CNID from database
          -> on mismatch: use CNID from file, update database (deleting both found CNIDs first)
          -> if no CNID in ad file: write CNID from database to ad file
          -> if no CNID in database: add CNID from ad file to database
          -> on no CNID at all: create one and store in both places
  OK F/D  Add found CNID, DID, filename, dev/inode, stamp to rebuild database
  OK F/D  Check/update stamp (implicitly done while checking CNIDs)


  2nd pass: Delete unused CNIDs
  -----------------------------

  St Spec
  -- ----
  OK Step through dbd (the one on disk) and rebuild-db from pass 1 and delete any CNID from
     dbd not in rebuild db. This in only done in exclusive mode.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#include <atalk/logger.h>
#include <atalk/cnid_dbd_private.h>
#include <atalk/volinfo.h>
#include "cmd_dbd.h"
#include "dbd.h"
#include "dbif.h"
#include "db_param.h"

#define LOCKFILENAME  "lock"
#define DBOPTIONS (DB_CREATE | DB_INIT_LOCK | DB_INIT_LOG | DB_INIT_MPOOL | DB_INIT_TXN)

static DBD *dbd;

volatile sig_atomic_t alarmed;
static int verbose;             /* Logging flag */
static int exclusive;           /* Exclusive volume access */
static struct db_param db_param = {
    NULL,                       /* Volume dirpath */
    1,                          /* bdb logfile autoremove */
    16384,                      /* bdb cachesize */
    -1,                         /* not used ... */
    -1,
    "",
    -1,
    -1,
    -1
};
static char dbpath[PATH_MAX];   /* Path to the dbd database */

/* 
   Provide some logging
 */
void dbd_log(enum logtype lt, char *fmt, ...)
{
    int len;
    static char logbuffer[1024];
    va_list args;

    if ( (lt == LOGSTD) || (verbose == 1)) {
        va_start(args, fmt);
        len = vsnprintf(logbuffer, 1023, fmt, args);
        va_end(args);
        logbuffer[1023] = 0;

        printf("%s\n", logbuffer);
    }
}

/* 
   SIGNAL handling:
   catch SIGINT and SIGTERM which cause clean exit. Ignore anything else.
 */

static void sig_handler(int signo)
{
    alarmed = 1;
    return;
}

void set_signal(void)
{
    struct sigaction sv;

    sv.sa_handler = sig_handler;
    sv.sa_flags = SA_RESTART;
    sigemptyset(&sv.sa_mask);
    if (sigaction(SIGTERM, &sv, NULL) < 0) {
        dbd_log( LOGSTD, "error in sigaction(SIGTERM): %s", strerror(errno));
        exit(EXIT_FAILURE);
    }        
    if (sigaction(SIGINT, &sv, NULL) < 0) {
        dbd_log( LOGSTD, "error in sigaction(SIGINT): %s", strerror(errno));
        exit(EXIT_FAILURE);
    }        

    memset(&sv, 0, sizeof(struct sigaction));
    sv.sa_handler = SIG_IGN;
    sigemptyset(&sv.sa_mask);

    if (sigaction(SIGABRT, &sv, NULL) < 0) {
        dbd_log( LOGSTD, "error in sigaction(SIGABRT): %s", strerror(errno));
        exit(EXIT_FAILURE);
    }        
    if (sigaction(SIGHUP, &sv, NULL) < 0) {
        dbd_log( LOGSTD, "error in sigaction(SIGHUP): %s", strerror(errno));
        exit(EXIT_FAILURE);
    }        
    if (sigaction(SIGQUIT, &sv, NULL) < 0) {
        dbd_log( LOGSTD, "error in sigaction(SIGQUIT): %s", strerror(errno));
        exit(EXIT_FAILURE);
    }        
}

int get_lock(const char *dbpath)
{
    int lockfd;
    char lockpath[PATH_MAX];
    struct flock lock;
    struct stat st;

    if ( (strlen(dbpath) + strlen(LOCKFILENAME+1)) > (PATH_MAX - 1) ) {
        dbd_log( LOGSTD, ".AppleDB pathname too long");
        exit(EXIT_FAILURE);
    }
    strncpy(lockpath, dbpath, PATH_MAX - 1);
    strcat(lockpath, "/");
    strcat(lockpath, LOCKFILENAME);

    if ((lockfd = open(lockpath, O_RDWR | O_CREAT, 0644)) < 0) {
        dbd_log( LOGSTD, "Error opening lockfile: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if ((stat(dbpath, &st)) != 0) {
        dbd_log( LOGSTD, "Error statting lockfile: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if ((chown(lockpath, st.st_uid, st.st_gid)) != 0) {
        dbd_log( LOGSTD, "Error inheriting lockfile permissions: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    
    lock.l_start  = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len    = 0;
    lock.l_type   = F_WRLCK;

    if (fcntl(lockfd, F_SETLK, &lock) < 0) {
        if (errno == EACCES || errno == EAGAIN) {
            if (exclusive) {
                dbd_log( LOGSTD, "Database is in use and exlusive was requested", strerror(errno));        
                exit(EXIT_FAILURE);
            };
        } else {
            dbd_log( LOGSTD, "Error getting fcntl F_WRLCK on lockfile: %s", strerror(errno));
            exit(EXIT_FAILURE);
       }
    }
    
    return lockfd;
}

void free_lock(int lockfd)
{
    struct flock lock;

    lock.l_start  = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len    = 0;
    lock.l_type = F_UNLCK;
    fcntl(lockfd, F_SETLK, &lock);
    close(lockfd);
}

static void usage ()
{
    printf("Usage: dbd [-e|-v|-x|-u] -d [-i] | -s | -r [-f] <path to netatalk volume>\n"
           "dbd can dump, scan, reindex and rebuild Netatalk dbd CNID databases.\n"
           "dbd must be run with appropiate permissions i.e. as root.\n\n"
           "Main commands are:\n"
           "   -d Dump CNID database\n"
           "      Option: -i dump indexes too\n"
           "   -s Scan volume:\n"
           "      1. Compare CNIDs in database with volume\n"
           "      2. Check if .AppleDouble dirs exist\n"
           "      3. Check if  AppleDouble file exist\n"
           "      4. Report orphaned AppleDouble files\n"
           "      5. Check for directories inside AppleDouble directories\n"
           "      6. Check name encoding by roundtripping, log on error\n"
           "      7. Check for orphaned CNIDs in database (requires -e)\n"
           "   -r Rebuild volume:\n"
           "      1. Sync CNIDSs in database with volume\n"
           "      2. Make sure .AppleDouble dir exist, create if missing\n"
           "      3. Make sure AppleDouble file exists, create if missing\n"
           "      4. Delete orphaned AppleDouble files\n"
           "      5. Check for directories inside AppleDouble directories\n"
           "      6. Check name encoding by roundtripping, log on error\n"
           "      7. Check for orphaned CNIDs in database (requires -e)\n"
           "      Option: -f wipe database and rebuild from IDs stored in AppleDouble files,\n"
           "                 only available for volumes with 'cachecnid' option. Implies -e.\n"
           "   -u Prepare upgrade:\n"
           "      Before installing an upgraded version of Netatalk that is linked against\n"
           "      a newer BerkeleyDB lib, run `dbd -u ...` from the OLD Netatalk pior to\n"
           "      upgrading on all volumes. This removes the BerkleyDB environment.\n"
           "      On exit cnid_dbd does this automatically, so normally calling dbd -u should not be necessary.\n\n"
           "General options:\n"
           "   -e only work on inactive volumes and lock them (exclusive)\n"
           "   -x rebuild indexes (just for completeness, mostly useless!)\n"
           "   -v verbose\n\n"
           "WARNING:\n"
           "If you want/need to run an -r -f rebuild after adding 'cachecnid' to a volume configuration,\n"
           "you must run a rebuild with -r alone at first in order to sync all existing CNIDs from the db\n"
           "to the AppleDouble files!\n"
        );
}

int main(int argc, char **argv)
{
    int c, lockfd, ret = -1;
    int dump=0, scan=0, rebuild=0, prep_upgrade=0, rebuildindexes=0, dumpindexes=0, force=0;
    dbd_flags_t flags = 0;
    char *volpath;
    struct volinfo volinfo;

    if (geteuid() != 0) {
        usage();
        exit(EXIT_FAILURE);
    }

    while ((c = getopt(argc, argv, ":dsruvxife")) != -1) {
        switch(c) {
        case 'd':
            dump = 1;
            break;
        case 'i':
            dumpindexes = 1;
            break;
        case 's':
            scan = 1;
            flags |= DBD_FLAGS_SCAN;
            break;
        case 'r':
            rebuild = 1;
            break;
        case 'u':
            prep_upgrade = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'e':
            exclusive = 1;
            flags |= DBD_FLAGS_EXCL;
            break;
        case 'x':
            rebuildindexes = 1;
            break;
        case 'f':
            force = 1;
            exclusive = 1;
            flags |= DBD_FLAGS_FORCE | DBD_FLAGS_EXCL;
            break;
        case ':':
        case '?':
            usage();
            exit(EXIT_FAILURE);
            break;
        }
    }

    if ((dump + scan + rebuild + prep_upgrade) != 1) {
        usage();
        exit(EXIT_FAILURE);
    }

    if ( (optind + 1) != argc ) {
        usage();
        exit(EXIT_FAILURE);
    }
    volpath = argv[optind];

    /* Remember cwd */
    int cdir;
    if ((cdir = open(".", O_RDONLY)) < 0) {
        dbd_log( LOGSTD, "Can't open dir: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
        
    /* Setup signal handling */
    set_signal();

    /* Setup logging. Should be portable among *NIXes */
    if (!verbose)
        setuplog("default log_info /dev/tty");
    else
        setuplog("default log_debug /dev/tty");

    /* Load .volinfo file */
    if (loadvolinfo(volpath, &volinfo) == -1) {
        dbd_log( LOGSTD, "Unkown volume options!");
        exit(EXIT_FAILURE);
    }
    if (vol_load_charsets(&volinfo) == -1) {
        dbd_log( LOGSTD, "Error loading charsets!");
        exit(EXIT_FAILURE);
    }

    /* Put "/.AppleDB" at end of volpath, get path from volinfo file */
    if ( (strlen(volinfo.v_dbpath) + strlen("/.AppleDB")) > (PATH_MAX - 1) ) {
        dbd_log( LOGSTD, "Volume pathname too long");
        exit(EXIT_FAILURE);        
    }
    strncpy(dbpath, volinfo.v_dbpath, PATH_MAX - 9 - 1);
    strcat(dbpath, "/.AppleDB");

    /* 
       Before we do anything else, check if there is an instance of cnid_dbd
       running already and silently exit if yes.
    */
    lockfd = get_lock(dbpath);

    /* Prepare upgrade ? */
    if (prep_upgrade) {
        if (dbif_prep_upgrade(dbpath))
            goto exit_failure;
        goto exit_success;
    }        

    /* Check if -f is requested and wipe db if yes */
    if ((flags & DBD_FLAGS_FORCE) && rebuild && (volinfo.v_flags & AFPVOL_CACHE)) {
        char cmd[8 + MAXPATHLEN];
        snprintf(cmd, 8 + MAXPATHLEN, "rm -f %s/*", dbpath);
        dbd_log( LOGDEBUG, "Removing old database of volume: '%s'", volpath);
        system(cmd);
        dbd_log( LOGDEBUG, "Removed old database.");
    }

    /* 
       Lets start with the BerkeleyDB stuff
    */
    if ((dbd = dbif_init(dbpath, "cnid2.db")) == NULL)
        goto exit_failure;

    if (dbif_env_open(dbd, &db_param, exclusive ? (DBOPTIONS | DB_RECOVER) : DBOPTIONS) < 0) {
        dbd_log( LOGSTD, "error opening database!");
        goto exit_failure;
    }

    if (exclusive)
        dbd_log( LOGDEBUG, "Finished recovery.");

    if (dbif_open(dbd, &db_param, rebuildindexes) < 0) {
        dbif_close(dbd);
        goto exit_failure;
    }

    if (dbd_stamp(dbd) < 0) {
        dbif_close(dbd);
        goto exit_failure;
    }

    if (dump) {
        if (dbif_dump(dbd, dumpindexes) < 0) {
            dbd_log( LOGSTD, "Error dumping database");
        }
    } else if (rebuild || scan) {
        if (cmd_dbd_scanvol(dbd, &volinfo, flags) < 0) {
            dbd_log( LOGSTD, "Error repairing database.");
        }
    }

    if (dbif_close(dbd) < 0) {
        dbd_log( LOGSTD, "Error closing database");
        goto exit_failure;
    }

exit_success:
    ret = 0;

exit_failure:
    free_lock(lockfd);
    
    if ((fchdir(cdir)) < 0)
        dbd_log(LOGSTD, "fchdir: %s", strerror(errno));

    if (ret == 0)
        exit(EXIT_SUCCESS);
    else
        exit(EXIT_FAILURE);
}