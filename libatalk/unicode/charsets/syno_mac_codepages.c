#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */
#include <stdlib.h>
#include <netatalk/endian.h>
#include <atalk/unicode.h>
#include <synosdk/unicode.h>
#include <syslog.h>
#include <string.h>

static size_t syno_mac_push (const char *szCpTo, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_pull (const char *szCpFrom, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_enu_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_enu_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_fre_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_fre_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_ger_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_ger_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_ita_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_ita_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_spn_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_spn_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_cht_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_cht_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_chs_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_chs_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_jpn_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_jpn_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_krn_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_krn_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_ptb_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_ptb_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_rus_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_rus_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_dan_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_dan_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_nor_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_nor_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_sve_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_sve_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_nld_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_nld_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_plk_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_plk_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_ptg_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_ptg_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_hun_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_hun_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_trk_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_trk_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_ara_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static size_t syno_mac_ara_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);

#if 0
struct charset_functions charset_syno_mac_greek =
{
	"1737",
	6,
	syno_mac_greek_pull,
	syno_mac_greek_push,
	CHARSET_CLIENT | CHARSET_MULTIBYTE | CHARSET_PRECOMPOSED
};
#endif

struct charset_functions charset_syno_mac_enu =
{
	"enu",
	0,
	syno_mac_enu_pull,
	syno_mac_enu_push,
	CHARSET_CLIENT | CHARSET_MULTIBYTE | CHARSET_PRECOMPOSED
};

struct charset_functions charset_syno_mac_fre =
{
	"fre",
	0,
	syno_mac_fre_pull,
	syno_mac_fre_push,
	CHARSET_CLIENT | CHARSET_MULTIBYTE | CHARSET_PRECOMPOSED
};

struct charset_functions charset_syno_mac_ger =
{
	"ger",
	0,
	syno_mac_ger_pull,
	syno_mac_ger_push,
	CHARSET_CLIENT | CHARSET_MULTIBYTE | CHARSET_PRECOMPOSED
};

struct charset_functions charset_syno_mac_ita =
{
	"ita",
	0,
	syno_mac_ita_pull,
	syno_mac_ita_push,
	CHARSET_CLIENT | CHARSET_MULTIBYTE | CHARSET_PRECOMPOSED
};

struct charset_functions charset_syno_mac_spn =
{
	"spn",
	0,
	syno_mac_spn_pull,
	syno_mac_spn_push,
	CHARSET_CLIENT | CHARSET_MULTIBYTE | CHARSET_PRECOMPOSED
};

struct charset_functions charset_syno_mac_cht =
{
	"cht",
	2,
	syno_mac_cht_pull,
	syno_mac_cht_push,
	CHARSET_CLIENT | CHARSET_MULTIBYTE | CHARSET_PRECOMPOSED
};

struct charset_functions charset_syno_mac_chs =
{
	"chs",
	25,
	syno_mac_chs_pull,
	syno_mac_chs_push,
	CHARSET_CLIENT | CHARSET_MULTIBYTE | CHARSET_PRECOMPOSED
};

struct charset_functions charset_syno_mac_jpn =
{
	"jpn",
	1,
	syno_mac_jpn_pull,
	syno_mac_jpn_push,
	CHARSET_CLIENT | CHARSET_MULTIBYTE | CHARSET_PRECOMPOSED
};

struct charset_functions charset_syno_mac_krn =
{
	"krn",
	3,
	syno_mac_krn_pull,
	syno_mac_krn_push,
	CHARSET_CLIENT | CHARSET_MULTIBYTE | CHARSET_PRECOMPOSED
};

struct charset_functions charset_syno_mac_ptb =
{
	"ptb",
	0,
	syno_mac_ptb_pull,
	syno_mac_ptb_push,
	CHARSET_CLIENT | CHARSET_MULTIBYTE | CHARSET_PRECOMPOSED
};

struct charset_functions charset_syno_mac_rus =
{
	"rus",
	7,
	syno_mac_rus_pull,
	syno_mac_rus_push,
	CHARSET_CLIENT | CHARSET_MULTIBYTE
};

struct charset_functions charset_syno_mac_dan =
{
	"dan",
	0,
	syno_mac_dan_pull,
	syno_mac_dan_push,
	CHARSET_CLIENT | CHARSET_MULTIBYTE | CHARSET_PRECOMPOSED
};

struct charset_functions charset_syno_mac_nor =
{
	"nor",
	0,
	syno_mac_nor_pull,
	syno_mac_nor_push,
	CHARSET_CLIENT | CHARSET_MULTIBYTE | CHARSET_PRECOMPOSED
};

struct charset_functions charset_syno_mac_sve =
{
	"sve",
	0,
	syno_mac_sve_pull,
	syno_mac_sve_push,
	CHARSET_CLIENT | CHARSET_MULTIBYTE | CHARSET_PRECOMPOSED
};

struct charset_functions charset_syno_mac_nld =
{
	"nld",
	0,
	syno_mac_nld_pull,
	syno_mac_nld_push,
	CHARSET_CLIENT | CHARSET_MULTIBYTE | CHARSET_PRECOMPOSED
};

struct charset_functions charset_syno_mac_plk =
{
	"plk",
	0,
	syno_mac_plk_pull,
	syno_mac_plk_push,
	CHARSET_CLIENT | CHARSET_MULTIBYTE | CHARSET_PRECOMPOSED
};

struct charset_functions charset_syno_mac_ptg =
{
	"ptg",
	0,
	syno_mac_ptg_pull,
	syno_mac_ptg_push,
	CHARSET_CLIENT | CHARSET_MULTIBYTE | CHARSET_PRECOMPOSED
};

struct charset_functions charset_syno_mac_hun =
{
	"hun",
	0,
	syno_mac_hun_pull,
	syno_mac_hun_push,
	CHARSET_CLIENT | CHARSET_MULTIBYTE | CHARSET_PRECOMPOSED
};

struct charset_functions charset_syno_mac_trk =
{
	"trk",
	35,
	syno_mac_trk_pull,
	syno_mac_trk_push,
	CHARSET_CLIENT | CHARSET_MULTIBYTE
};

struct charset_functions charset_syno_mac_ara =
{
	"ara",
	4,
	syno_mac_ara_pull,
	syno_mac_ara_push,
	CHARSET_CLIENT | CHARSET_MULTIBYTE
};

static size_t syno_mac_push (const char *szCpTo, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	char *szInput;
	char *szUTF8;
	size_t UCSlen = 0, UTF8len = 0;
	size_t ret = (size_t)-1;
	SYNO_CODEPAGE slcpTo = -1;

	if ( (NULL == szCpTo) || 0 >= (*inbytesleft) || 0 >= (*outbytesleft) )
		return (size_t)-1;


	slcpTo = SLIBCCodepageValueParse(SYNO_CODEPAGE_MAC, szCpTo);
	if ( -1 == slcpTo ) {
		return (size_t) -1;
	}

	UCSlen = *inbytesleft;
	szInput = (char *)malloc(sizeof(char) * (UCSlen+1)  );
	if ( szInput == (char *) NULL )
	{
		syslog(LOG_ERR, "%s:%d(%s): malloc szInput error, UCSlen=[%d]", __FILE__, __LINE__, __FUNCTION__, UCSlen+1);
		goto SZINPUT_MALLOC_ERROR;
	}

	szUTF8 = (char *)malloc(sizeof(char) * (UCSlen*3+1) ); // 6 * ASCII len
	if ( szUTF8 == (char *) NULL )
	{
		syslog(LOG_ERR, "%s:%d(%s): malloc szUTF8 error, UCSlen=[%d]", __FILE__, __LINE__, __FUNCTION__, UCSlen);
		goto SZUTF8_MALLOC_ERROR;
	}

	memcpy( szInput, *inbuf, UCSlen);
	szInput[UCSlen]=0;

	UTF8len = convert_string(CH_UCS2, CH_UTF8, szInput, UCSlen, szUTF8, UCSlen * 3 + 1);
	if ( UTF8len == (size_t) -1 )
	{
		syslog(LOG_ERR, "%s:%d(%s): convert_string from CH_UCS2 to CH_UTF8 fail", __FILE__, __LINE__, __FUNCTION__);
		goto CONVERT_ERROR;
	}
	szUTF8[UTF8len] = 0;

	ret = SLIBCUnicodeStrUTF8ToCP(slcpTo, szUTF8, *outbuf, *outbytesleft);
	if ( ret == (size_t) -1 )
	{
		syslog(LOG_ERR, "%s:%d(%s): SLIBCUnicodeStrUTF8ToCP codepage[%d] fail, szUTF8=[%s]", __FILE__, __LINE__, __FUNCTION__, slcpTo, szUTF8);
		goto CONVERT_ERROR;
	}

	(*outbuf)[ret] = 0;
	*inbuf += UCSlen;
	*inbytesleft -= UCSlen;
	*outbuf += ret;
	*outbytesleft -= ret;
CONVERT_ERROR:
	free(szUTF8);
SZUTF8_MALLOC_ERROR:
	free(szInput);
SZINPUT_MALLOC_ERROR:
	return ret;
}

static size_t syno_mac_pull ( const char *szCpFrom , char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	char *szInput;
	char *szUTF8;
	size_t CPlen = 0, UTF8len = 0;
	size_t ret = (size_t)-1;
	SYNO_CODEPAGE slcpFrom = -1;

	if ( (NULL == szCpFrom) || 0 >= (*inbytesleft) || 0 >= (*outbytesleft) )
		return (size_t)-1;

	slcpFrom = SLIBCCodepageValueParse(SYNO_CODEPAGE_MAC, szCpFrom);
	if ( -1 == slcpFrom ) {
		return (size_t) -1;
	}

	CPlen = *inbytesleft;
	szInput = (char *)malloc(sizeof(char) * (CPlen+1)  );
	if ( szInput == (char *) NULL )
	{
		syslog(LOG_ERR, "%s:%d(%s): malloc szInput error, CPlen=[%d]", __FILE__, __LINE__, __FUNCTION__, CPlen+2);
		goto SZINPUT_MALLOC_ERROR;
	}

	szUTF8 = (char *)malloc(sizeof(char) * (CPlen * 6 + 1) );
	if ( szUTF8 == (char *) NULL )
	{
		syslog(LOG_ERR, "%s:%d(%s): malloc szUTF8 error, CPlen=[%d]", __FILE__, __LINE__, __FUNCTION__, CPlen * 6 + 1 );
		goto SZUTF8_MALLOC_ERROR;
	}

	memcpy( szInput, *inbuf, CPlen);
	szInput[CPlen]=0;

	UTF8len = SLIBCUnicodeStrCPToUTF8(slcpFrom, szInput, szUTF8, CPlen*6+1);
	if ( UTF8len == (size_t) -1 )
	{
		syslog(LOG_ERR, "%s:%d(%s): SLIBCUnicodeStrCPToUTF8 codepage[%d] fail, szInput=[%s]", __FILE__, __LINE__, __FUNCTION__, slcpFrom, szInput);
		goto CONVERT_ERROR;
	}

	ret = convert_string(CH_UTF8, CH_UCS2, szUTF8, UTF8len, (ucs2_t *)*outbuf, *outbytesleft);
	if ( ret == (size_t) -1 )
	{
		syslog(LOG_ERR, "%s:%d(%s): convert_string from CH_UTF8 to CH_UCS2 fail, szUTF8=[%s]", __FILE__, __LINE__, __FUNCTION__, szUTF8);
		goto CONVERT_ERROR;
	}

	(*outbuf)[ret] = 0;
	*inbuf += CPlen;
	*inbytesleft -= CPlen;
	*outbuf += ret;
	*outbytesleft -= ret;
CONVERT_ERROR:
	free(szUTF8);
SZUTF8_MALLOC_ERROR:
	free(szInput);
SZINPUT_MALLOC_ERROR:
	return ret;
}

static size_t syno_mac_enu_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_push("enu", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_enu_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_pull("enu", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_fre_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_push("fre", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_fre_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_pull("fre", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_ger_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_push("ger", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_ger_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_pull("ger", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_ita_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_push("ita", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_ita_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_pull("ita", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_spn_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_push("spn", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_spn_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_pull("spn", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_cht_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_push("cht", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_cht_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_pull("cht", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_chs_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_push("chs", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_chs_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_pull("chs", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_jpn_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_push("jpn", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_jpn_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_pull("jpn", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_krn_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_push("krn", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_krn_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_pull("krn", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_ptb_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_push("ptb", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_ptb_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_pull("ptb", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_rus_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_push("rus", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_rus_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_pull("rus", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_dan_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_push("dan", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_dan_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_pull("dan", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_nor_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_push("nor", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_nor_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_pull("nor", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_sve_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_push("sve", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_sve_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_pull("sve", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_nld_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_push("nld", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_nld_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_pull("nld", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_plk_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_push("plk", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_plk_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_pull("plk", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_ptg_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_push("ptg", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_ptg_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_pull("ptg", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_hun_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_push("hun", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_hun_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_pull("hun", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_trk_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_push("trk", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_trk_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_pull("trk", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_ara_push ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_push("ara", inbuf, inbytesleft, outbuf, outbytesleft);
}

static size_t syno_mac_ara_pull ( void *cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
	return syno_mac_pull("ara", inbuf, inbytesleft, outbuf, outbytesleft);
}

