#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <string.h>
#include <atalk/adouble.h>

#define FILEIOFF_ATTR 14
#define AFPFILEIOFF_ATTR 2

#ifdef MY_ABC_HERE
#include <sys/types.h>
#include <attr/xattr.h>
#include <synosdk/ea.h>
#endif
/* 
   Note:
   the "shared" and "invisible" attributes are opaque and stored and
   retrieved from the FinderFlags. This fixes Bug #2802236:
   <https://sourceforge.net/tracker/?func=detail&aid=2802236&group_id=8642&atid=108642>
 */
#ifdef MY_ABC_HERE
#include <atalk/logger.h>
#include <linux/stat.h>
#include <asm/unistd.h>
#include <stdint.h>
#include <synoacl.h>
#include <synosdk/file.h>
#define MODE_WRITEALL			(S_IWUSR | S_IWGRP | S_IWOTH)
#define ATTR_LOCK				(ATTRBIT_NOWRITE | ATTRBIT_NORENAME | ATTRBIT_NODELETE)
#define FILEI_ATTROFF(ad)		(ad_entry(ad, ADEID_FILEI) + FILEIOFF_ATTR)
#define AFPFILEI_ATTROFF(ad)	(ad_entry(ad, ADEID_AFPFILEI) + AFPFILEIOFF_ATTR)
#define FINDERI_ATTROFF(ad)		(ad_entry(ad, ADEID_FINDERI) + FINDERINFO_FRFLAGOFF)

#define SYNO_SMBATTR_HIDE	1<<0
#define SYNO_SMBATTR_RO		1<<1

void synoSmbAttrGet(const char *filename, struct adouble *ad)
{
	SYNOSTAT stOrig;
	BZERO_STRUCT(stOrig);

	if (!ad) {
		goto END;
	}
	ad->ad_smb_attr = 0;
	if (NULL == filename || '\0' == filename[0]) {
		goto END;
	} else if (0 != SLIBCFileStat(filename, SYNOST_STAT | SYNOST_ARBIT, &stOrig)) {
		LOG(log_warning, logtype_default, "[%s] not exist! %m", filename);
		goto END;
	}
	// check hidden bit
	if (stOrig.ext.archBit & S2_SMB_HIDDEN) {
		ad->ad_smb_attr |= (SYNO_SMBATTR_HIDE);
	}
	// check ReadOnly
	#ifdef MY_ABC_HERE
	if (SYNOACLIsSupport(filename, -1, SYNO_ACL_IS_FILE_SUPPORT)) {
		if (stOrig.ext.archBit & S2_SMB_READONLY) {
			ad->ad_smb_attr |= (SYNO_SMBATTR_RO);
		}
	} else 
	#endif
	if (!(stOrig.st.st_mode & (MODE_WRITEALL))) {
		ad->ad_smb_attr |= (SYNO_SMBATTR_RO);
	}
	ad->ad_smb_over = 1;
END:
	return;
}

static void synoSmbAttrSet(const char *filename, int smbattr)
{
	struct stat stOrig;
	if (NULL == filename || '\0' == filename[0]) {
		goto END;
	} else if (0 != stat(filename, &stOrig)) {
		LOG(log_warning, logtype_default, "[%s] not exist! %m", filename);
		goto END;
	}

	// sync SMB's hidden bit
	if (smbattr & (SYNO_SMBATTR_HIDE)) {
		SYNOArchiveBit(filename, F_SETSMB_HIDDEN);
	} else {
		SYNOArchiveBit(filename, F_CLRSMB_HIDDEN);
	}

	// sync SMB's ReadOnly
	#ifdef MY_ABC_HERE
	if (SYNOACLIsSupport(filename, -1, SYNO_ACL_IS_FILE_SUPPORT)) {
		if (smbattr & (SYNO_SMBATTR_RO)) {
			SYNOArchiveBit(filename, F_SETSMB_READONLY);
		} else {
			SYNOArchiveBit(filename, F_CLRSMB_READONLY);
		}
	} else
	#endif
	if (smbattr & (SYNO_SMBATTR_RO)) {
		if (0 != chmod(filename, stOrig.st_mode & ~(MODE_WRITEALL))) {
			LOG(log_warning, logtype_default, "Fail to set mod of %s. %m", filename);
		}
	} else {
		if (0 != chmod(filename, stOrig.st_mode | (MODE_WRITEALL))) {
			LOG(log_warning, logtype_default, "Fail to set mod of %s. %m", filename);
		}
	}

END:
	return;
}
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
static void synoGetXATTR(const struct adouble *ad, u_int16_t *flags)
{
	ssize_t xattr_len = 0;
	char xattr_data[32] = {0};

	memset(flags, 0, sizeof(*flags));
	xattr_len = getxattr(ad->ad_df_path, SZ_XATTR_FINDERINFO, xattr_data, sizeof(xattr_data));
	if (0 < xattr_len) {
		memcpy(flags, xattr_data + FINDERINFO_FRFLAGOFF, sizeof(*flags));
	} else if (0 > xattr_len) {
		LOG(log_warning, logtype_default, "%m, Fail to get xattr of [%s]!", ad->ad_df_path);
	}
}
#endif
int ad_getattr(struct adouble *ad, u_int16_t *attr)
{
    u_int16_t fflags;
    *attr = 0;

    if (ad->ad_version == AD_VERSION1) {
        if (ad_getentryoff(ad, ADEID_FILEI)) {
            memcpy(attr, ad_entry(ad, ADEID_FILEI) + FILEIOFF_ATTR,
                   sizeof(u_int16_t));
        }
    }
#if AD_VERSION == AD_VERSION2
    else if (ad->ad_version == AD_VERSION2) {
#ifdef MY_ABC_HERE
        if (ad_getentryoff(ad, ADEID_AFPFILEI) && ad_getentryoff(ad, ADEID_FINDERI)) {
            memcpy(attr, ad_entry(ad, ADEID_AFPFILEI) + AFPFILEIOFF_ATTR, 2);
		}
		if (ad_getentryoff(ad, ADEID_FINDERI)) 
#else
        if (ad_getentryoff(ad, ADEID_AFPFILEI))
#endif
		{
#ifndef MY_ABC_HERE
            memcpy(attr, ad_entry(ad, ADEID_AFPFILEI) + AFPFILEIOFF_ATTR, 2);
#endif

            /* Now get opaque flags from FinderInfo */
            memcpy(&fflags, ad_entry(ad, ADEID_FINDERI) + FINDERINFO_FRFLAGOFF, 2);
            if (fflags & htons(FINDERINFO_INVISIBLE))
                *attr |= htons(ATTRBIT_INVISIBLE);
            else
                *attr &= htons(~ATTRBIT_INVISIBLE);
 /*
   This one is tricky, I actually got it wrong the first time:
   for directories bit 1<<1 is ATTRBIT_EXPFLDR and is NOT opaque !
 */
            if ( ! (ad->ad_adflags & ADFLAGS_DIR)) {
                if (fflags & htons(FINDERINFO_ISHARED))
                    *attr |= htons(ATTRBIT_MULTIUSER);
                else
                    *attr &= htons(~ATTRBIT_MULTIUSER);
            }
	#ifdef MY_ABC_HERE
			// FIXME hfsplus also support this ? should we just skip the following ?
			if (0 == ad->ad_smb_over) {
				synoSmbAttrGet(ad->ad_df_path, ad);
			}
			if ((ad->ad_smb_attr & (SYNO_SMBATTR_HIDE)) || (*attr & htons(ATTRBIT_INVISIBLE))) {
				*attr |= htons(ATTRBIT_INVISIBLE);
				*FINDERI_ATTROFF(ad) |= htons(FINDERINFO_INVISIBLE);
			}
			if ((ad->ad_smb_attr & (SYNO_SMBATTR_RO)) || (*attr & htons(ATTR_LOCK))) {
				*attr |= htons(ATTR_LOCK);
				*AFPFILEI_ATTROFF(ad) |= htons(ATTR_LOCK);
			}
	#endif
        }
    }
#endif
    else
        return -1;

    *attr |= htons(ad->ad_open_forks);

    return 0;
}

#ifdef MY_ABC_HERE
static void synoSetXATTR(const struct adouble *ad, u_int16_t flags)
{
	ssize_t xattr_len = 0;
	char xattr_data[32] = {0};

	xattr_len = getxattr(ad->ad_df_path, SZ_XATTR_FINDERINFO, xattr_data, sizeof(xattr_data));
	if (0 >= xattr_len) {
		LOG(log_error, logtype_default, "%m, Fail to get xattr of [%s]!", ad->ad_df_path);
		return;
	}

	memcpy(xattr_data + FINDERINFO_FRFLAGOFF, &flags, sizeof(flags));
	if (0 > setxattr(ad->ad_df_path, SZ_XATTR_FINDERINFO, xattr_data, sizeof(xattr_data), 0)) {
		LOG(log_error, logtype_default, "%m, Fail to get xattr of [%s]!", ad->ad_df_path);
		return;
	}

	sync();
}
#endif
/* ----------------- */
int ad_setattr(const struct adouble *ad, const u_int16_t attribute)
{
    uint16_t fflags;
#ifdef MY_ABC_HERE
	int smbattr = 0;
#endif

    /* we don't save open forks indicator */
    u_int16_t attr = attribute & ~htons(ATTRBIT_DOPEN | ATTRBIT_ROPEN);

    /* Proactively (10.4 does indeed try to set ATTRBIT_MULTIUSER (=ATTRBIT_EXPFLDR)
       for dirs with SetFile -a M <dir> ) disable all flags not defined for dirs. */
    if (ad->ad_adflags & ADFLAGS_DIR)
        attr &= ~(ATTRBIT_MULTIUSER | ATTRBIT_NOWRITE | ATTRBIT_NOCOPY);

    if (ad->ad_version == AD_VERSION1) {
        if (ad_getentryoff(ad, ADEID_FILEI)) {
            memcpy(ad_entry(ad, ADEID_FILEI) + FILEIOFF_ATTR, &attr,
                   sizeof(attr));
        }
    }
#if AD_VERSION == AD_VERSION2
    else if (ad->ad_version == AD_VERSION2) {
        if (ad_getentryoff(ad, ADEID_AFPFILEI) && ad_getentryoff(ad, ADEID_FINDERI)) {
            memcpy(ad_entry(ad, ADEID_AFPFILEI) + AFPFILEIOFF_ATTR, &attr, sizeof(attr));
#ifdef MY_ABC_HERE
		}
        if (ad_getentryoff(ad, ADEID_FINDERI)) {
#endif
            
            /* Now set opaque flags in FinderInfo too */
            memcpy(&fflags, ad_entry(ad, ADEID_FINDERI) + FINDERINFO_FRFLAGOFF, 2);
            if (attr & htons(ATTRBIT_INVISIBLE))
                fflags |= htons(FINDERINFO_INVISIBLE);
            else
                fflags &= htons(~FINDERINFO_INVISIBLE);

            /* See above comment in ad_getattr() */
            if (attr & htons(ATTRBIT_MULTIUSER)) {
                if ( ! (ad->ad_adflags & ADFLAGS_DIR) )
                    fflags |= htons(FINDERINFO_ISHARED);
            } else
                    fflags &= htons(~FINDERINFO_ISHARED);

            memcpy(ad_entry(ad, ADEID_FINDERI) + FINDERINFO_FRFLAGOFF, &fflags, 2);
#ifdef MY_ABC_HERE
			smbattr |= (attr & htons(ATTRBIT_INVISIBLE)) ? (SYNO_SMBATTR_HIDE) : 0;
			smbattr |= (attr & htons(ATTR_LOCK)) ? (SYNO_SMBATTR_RO) : 0;
			synoSmbAttrSet(ad->ad_df_path, smbattr);
#endif
        }
    }
#endif
    else
        return -1;

    return 0;
}

/* --------------
 * save file/folder ID in AppleDoubleV2 netatalk private parameters
 * return 1 if resource fork has been modified
 */
#if AD_VERSION == AD_VERSION2
int ad_setid (struct adouble *adp, const dev_t dev, const ino_t ino , const u_int32_t id, const cnid_t did, const void *stamp)
{
    if ((adp->ad_flags == AD_VERSION2) && (adp->ad_options & ADVOL_CACHE)) {

        /* ad_getid depends on this to detect presence of ALL entries */
        ad_setentrylen( adp, ADEID_PRIVID, sizeof(id));
        memcpy(ad_entry( adp, ADEID_PRIVID ), &id, sizeof(id));

        ad_setentrylen( adp, ADEID_PRIVDEV, sizeof(dev_t));
        if ((adp->ad_options & ADVOL_NODEV)) {
            memset(ad_entry( adp, ADEID_PRIVDEV ), 0, sizeof(dev_t));
        } else {
            memcpy(ad_entry( adp, ADEID_PRIVDEV ), &dev, sizeof(dev_t));
        }

        ad_setentrylen( adp, ADEID_PRIVINO, sizeof(ino_t));
        memcpy(ad_entry( adp, ADEID_PRIVINO ), &ino, sizeof(ino_t));

        ad_setentrylen( adp, ADEID_DID, sizeof(did));
        memcpy(ad_entry( adp, ADEID_DID ), &did, sizeof(did));

        ad_setentrylen( adp, ADEID_PRIVSYN, ADEDLEN_PRIVSYN);
        memcpy(ad_entry( adp, ADEID_PRIVSYN ), stamp, ADEDLEN_PRIVSYN);
        return 1;
    }
    return 0;
}

/* ----------------------------- */
u_int32_t ad_getid (struct adouble *adp, const dev_t st_dev, const ino_t st_ino , const cnid_t did, const void *stamp)
{
    u_int32_t aint = 0;
    dev_t  dev;
    ino_t  ino;
    cnid_t a_did;
    char   temp[ADEDLEN_PRIVSYN];

    /* look in AD v2 header
     * note inode and device are opaques and not in network order
     * only use the ID if adouble is writable for us.
     */
    if (adp
        && (adp->ad_options & ADVOL_CACHE)
        && (adp->ad_md->adf_flags & O_RDWR )
        && (sizeof(dev_t) == ad_getentrylen(adp, ADEID_PRIVDEV)) /* One check to ensure ALL values are there */
        ) {
        memcpy(&dev, ad_entry(adp, ADEID_PRIVDEV), sizeof(dev_t));
        memcpy(&ino, ad_entry(adp, ADEID_PRIVINO), sizeof(ino_t));
        memcpy(temp, ad_entry(adp, ADEID_PRIVSYN), sizeof(temp));
        memcpy(&a_did, ad_entry(adp, ADEID_DID), sizeof(cnid_t));

        if ( ((adp->ad_options & ADVOL_NODEV) || dev == st_dev)
             && ino == st_ino
             && (!did || a_did == did)
             && (memcmp(stamp, temp, sizeof(temp)) == 0) ) {
            memcpy(&aint, ad_entry(adp, ADEID_PRIVID), sizeof(aint));
            return aint;
        }
    }
    return 0;
}

/* ----------------------------- */
u_int32_t ad_forcegetid (struct adouble *adp)
{
    u_int32_t aint = 0;

    if (adp && (adp->ad_options & ADVOL_CACHE)) {
        memcpy(&aint, ad_entry(adp, ADEID_PRIVID), sizeof(aint));
        return aint;
    }
    return 0;
}
#endif

/* -----------------
 * set resource fork filename attribute.
 */
int ad_setname(struct adouble *ad, const char *path)
{
    int len;
    if ((len = strlen(path)) > ADEDLEN_NAME)
        len = ADEDLEN_NAME;
    if (path && ad_getentryoff(ad, ADEID_NAME)) {
        ad_setentrylen( ad, ADEID_NAME, len);
        memcpy(ad_entry( ad, ADEID_NAME ), path, len);
        return 1;
    }
    return 0;
}
